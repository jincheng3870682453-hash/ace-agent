# 安全策略(Security Policy)

ACE 把“权限/沙箱/回滚下沉到执行层”当第一原则,因此安全反馈会严肃对待。

## 报告漏洞

- 请勿公开透露未修复漏洞细节;优先创建 **Private vulnerability report**(GitHub 仓库 Settings → Security → Vulnerability alerts → New draft security advisory),或直接邮件维护者。
- 请附:触发条件(最好是可复现的最小代码片段)、影响、你运行的环境(OS/Python/是否开沙箱档)。

## 我们承诺

- 确认后 7 天内给出修复计划;P0(可致 RCE/越界读/凭据泄漏)会优先处理并尽快发补丁。
- 修复会补回归测试并记入 CHANGELOG(安全条目)。

## 已知边界(非漏洞)

- 不开 `--sandbox docker/job` 时,`code_execute`/`terminal_exec` 只是进程内策略层,**不是 OS 级隔离**(详见 README「安全模型」)。这类用法下的逃逸属设计边界,部署方应开对应沙箱档。
