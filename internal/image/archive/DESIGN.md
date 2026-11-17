# 镜像归档解析设计说明

`internal/image/archive` 把三种来源的镜像归档解析成同一种内部表示：

- `docker save` 导出的归档（含 docker 25 之前的 legacy 布局和 docker 25+ 的 OCI 布局 + manifest.json 混合布局）
- OCI 镜像目录（`oci-dir`，index.json + blobs/ 的目录形态）和 OCI 归档（tar 形态）
- `podman save` 导出的归档（manifest.json + 扁平 `<diffid>.tar` 层文件）

解析结果再经 `internal/source/archive.go` 适配成 stereoscope 的 `image.Image`，下游（分析、TUI、CI、导出）完全不感知来源差异。

## 统一表示与来源保留

统一的内部表示是 `archive.Image`：

- `Source`：来源路径、布局格式（`docker-save` / `oci`）、选中的 OCI 清单摘要和平台。所有错误信息都以前缀带上来源，并能进一步定位到具体文档（`manifest.json`、`index.json`、`config <digest>`、`layer N (<digest>)`）。
- `Config` / `Manifest`：原始配置 JSON 和选中的 OCI 清单原文，原样保留。
- `History`：配置里的完整历史（含空层项）。
- `Layers`：按构建顺序排列；每层带 DiffID（未压缩摘要）、Digest（存储形态摘要）、存储大小、嗅探出的媒体类型、配对后的构建命令，以及一个打开层内容的 `Open`。

## 层顺序：以谁为准，矛盾即报错

三种来源给出层顺序的依据不一样：docker/podman 归档看 `manifest.json` 的 `Layers`；OCI 要先经 `index.json` 选清单，再看清单的 `layers`；而配置里的 `rootfs.diff_ids` 又给出一份顺序。规则是：

1. **清单元数据是顺序的唯一权威**：docker/podman 用 `manifest.json`，OCI 用选中清单的 `layers`。docker 25+ 的归档同时有 `manifest.json` 和 `index.json` 时，`manifest.json` 优先（与 docker 本身及此前 stereoscope 的行为一致）。
2. **`rootfs.diff_ids` 只做交叉校验**：解析时逐层算出未压缩摘要，与 `diff_ids` 按位置比对。数量不符或任一位置不符，都返回"inconsistent archive"错误，点名 `manifest.json`（或 OCI 清单）和配置两份数据，**不悄悄挑一个用**。配置完全没有 `diff_ids` 时视为"无可校验"，按清单顺序继续。

## 历史与层的配对

配置里的 `history` 和文件系统层不是一一对应的：`empty_layer: true` 的历史项（ENV、LABEL、CMD 等只改配置的指令）不占层。配对时跳过空层项，按顺序把非空历史项配给各层；历史比层短时，多余的层标记为 `(missing)`（历史本身是可选的，容忍缺失，但不错位）。这是最容易错位的地方——直接按下标对齐会在第一个空层之后全部错一格。

## OCI 索引：平台选择与嵌套

- 用户指定了平台（`--platform`）就按指定的选；没指定按本机平台（`runtime.GOOS/GOARCH`）。
- 描述符不带 platform 字段时无法证伪，作为候选兜底，但任何精确匹配都排在它前面。
- `unknown/unknown` 是 attestation 清单的约定，永不选择。
- 索引可以嵌套（如 containerd 镜像存储的 `docker save`：外层索引指向多平台索引）。按内容判断嵌套（有 `manifests` 键是索引，有 `layers` 是清单），递归跟随，深度上限 8，超限报错。
- 一个都匹配不上时报错，并列出索引里出现过的所有平台。
- docker 归档只有一个镜像，不做平台选择（`source.Load` 会在平台不符时提示，与之前行为一致）。

## 摘要校验

OCI 的 content 按摘要寻址，读取时全部校验：

- 清单、配置、嵌套索引等 JSON blob：读入内存后立即校验 sha256，不符则报"the archive may be corrupt"。
- 层 blob：spool（落盘）或读取时流式校验存储摘要；解压后再算 DiffID 与配置交叉校验（见上）。
- docker/podman 归档的层没有寻址摘要可校验，校验就是 `diff_ids` 交叉检查。
- 摘要字符串先严格校验格式（`sha256:` + 64 位十六进制）再用于拼路径，`sha256:../x` 这类构造在变成文件路径之前就会被拒。

## 压缩格式：嗅探内容，不信媒体类型

层支持不压缩、gzip、zstd 三种。判断依据是内容开头的魔数（`1f 8b` / `28 b5 2f fd`），**不看清单里的媒体类型字符串**——它只是声明，可能不准（测试里专门有一个"标着未压缩的 gzip 层"用例）。外层归档（`.tar.gz` 等）走同一套嗅探。

## 流式处理：两条路的取舍

tar 条目顺序不固定，`manifest.json` 可能排在最后，单遍扫描不可能既流式又按需。两条候选路线：

| | 先扫描元数据再按需读层（本实现） | 整个输入先存临时文件 |
|---|---|---|
| 内存 | 只缓冲元数据（单文件 ≤8MiB，总量 ≤64MiB，超限报错） | 同样只缓冲元数据 |
| 磁盘 | 仅层有效载荷（spool 到临时目录） | 整个归档（含元数据，可能多几个 GiB） |
| 耗时 | 两遍顺序读（第一遍只读头和小文件，第二遍只取层）+ 每层一次解压校验 | 一遍读 + 一遍写，之后随机访问 |
| 随机访问 | 不需要（输入本来就是文件，重开即可） | 可以，但本需求用不到 |

选第一条：**第一遍**流式扫描，缓冲所有小文件（清单、索引、配置），只记录大条目（层）的名字和大小；**第二遍**重开文件，把需要的层流式拷进临时目录（spool），边拷边算摘要。层在 tar 里本来就是连续存储，第二遍仍是顺序读，不需要随机访问，所以"先整个落盘"买来的随机访问没有收益，磁盘占用却翻倍。

`Options.OnDemand` 保留了第二种懒策略的变体：不 spool，每次 `Layer.Open` 重开归档扫到对应条目。零临时磁盘、解析期零解压，但每次 Open 都是 O（归档大小） 的扫描，且摘要校验（含顺序交叉检查）推迟到读层时才发生——解析返回的 DiffID/Digest/媒体类型是归档的未验证声明。适合只读个别层的场景，默认不用。

OCI 目录不涉及这个问题：blob 按摘要直接寻址，无需 spool，解析期只做流式校验。

## 路径安全

- tar 条目名逐一校验：绝对路径、任何 `..` 路径元素都直接拒绝（"unsafe tar entry"）。
- 条目名永不作为文件系统路径使用：spool 文件按 `layer-*` 随机命名，OCI blob 路径只由校验过的摘要拼出。
- 归档里非普通文件/目录的条目（符号链接、设备等）一律拒绝。

## 三条读取路径的合并：决策与风险

**决策：合并。** docker-archive、oci-archive、oci-dir 三个 source 现在共用同一个解析器，差异只剩入口约束（`oci-archive`/`oci-dir` 要求 OCI 布局，`docker-archive` 两种布局都接受，与之前 docker→oci 两级 fallback 的接受范围一致）。守护进程、registry 等来源传输方式根本不同，不在合并范围内，仍走 stereoscope。

收益：

- 顺序、配对、校验、嗅探规则只有一份，不会再出现"docker 路径修好了、OCI 路径还错着"的分叉。
- 错误信息统一带来源和出错文档。

风险与对策：

- **行为漂移**：stereoscope 的解析器容忍一些古怪归档（kaniko 的 `sha256:<hex>` 配置名、containerd 存储的嵌套索引 + attestation、estargz 层、多镜像 tar）。对策是兼容测试全部保留并通过：`cmd/dive/cli` 的 golden 测试（kaniko、containerd 存储、estargz/zstd、legacy save）原样通过；解析器按名字跟随 `manifest.json`，不假设任何命名约定。
- **接受范围变宽**：`oci-archive://` 之前拒绝纯 docker 归档，现在按内容嗅探后仍拒绝（要求 OCI 布局）；`docker-archive://` 接受范围不变。失败时上报的 source 事件从 `docker-archive`+`oci-archive` 两次尝试变为单次 `docker-archive`（UI 行数变化，属内部行为）。
- **性能**：spool 模式比 stereoscope 多一遍顺序读和一遍解压校验。小镜像无感；几个 GiB 的镜像是秒级差异，换来的是解析期就能发现损坏和顺序矛盾，而不是分析到一半才炸。
- **双解析器并存**：stereoscope 仍用于守护进程/registry 来源，归档解析器是新增维护面。通过共享 fixture（`internal/imagefixture`）和跨格式一致性测试控制。

## 测试

`internal/image/archive` 的测试全部本地完成，不依赖任何后台服务：

- 用 `internal/imagefixture` 在内存里生成小镜像（层里少量文件，历史里故意插入空层项），分别打包成 docker legacy save、podman save、docker 25+ save、OCI 归档（不压缩/gzip/zstd）、OCI 目录，断言解析出的层序列、各层构建命令、层摘要完全一致。
- 异常输入：清单与配置顺序冲突、diff_ids 数量不符、层/配置 blob 被篡改、上跳路径条目、摘要穿越、无匹配平台（并校验错误列出可用平台）、索引嵌套超限、多镜像归档、非 tar/非镜像输入、外层 gzip 的归档。
