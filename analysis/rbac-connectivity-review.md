# RBAC + Connectivity Review — `edgescaleai/-adr-review-sandbox`

## Scope

This document surveys identity, RBAC, and network connectivity choices
made across the Pulumi, Terraform, and Omni examples in this repo.
It is descriptive, not prescriptive — no example is modified.
Findings are grouped into four sections plus a list of themes worth
turning into ADRs later.

The repo is a sandbox copy of `siderolabs/contrib`. Every cloud example
provisions a Talos Linux cluster and uses the Terraform/Pulumi Talos
provider to generate machine and client configuration. That shared
baseline is documented once in §2 and then differences are called out
per example.

## 1. Cloud IAM / service identity

| Example | Cloud-side IAM defined? | Granted to nodes | Provisioning credential |
|---|---|---|---|
| `examples/terraform/aws` | Yes — two policies, opt-in via `var.ccm` | EC2 instance profile, CCM policy | Provider env vars |
| `examples/terraform/azure` | No | n/a (SSH disabled, Talos-managed) | Provider env vars |
| `examples/terraform/hcloud` | No | n/a | `hcloud_token` |
| `examples/terraform/vultr` | No | n/a | Vultr API token |
| `examples/terraform/equinix-metal` | No | n/a | `em_api_token` (sensitive) |
| `examples/pulumi/azure` | No | n/a | Pulumi Azure config |
| `examples/pulumi/gcp` | No | n/a | Pulumi GCP config |
| `examples/pulumi/equinix-metal` | No | n/a | Equinix Metal token in stack config |
| `examples/omni` | n/a (delegated to Omni) | n/a | `omnictl` auth token |

### Findings

- **AWS is the only example that grants IAM to cluster nodes.**
  `examples/terraform/aws/main.tf:143-221` defines the control-plane
  CCM policy and `:224-252` defines the worker policy. Both are
  attached only when `var.ccm = true` (default `false`,
  `examples/terraform/aws/variables.tf:7-11`). The control-plane
  policy lists 40+ EC2/ELB/ASG actions on `Resource = "*"` — this
  is required by the upstream `cloud-provider-aws` and matches its
  documented prerequisites, but it is broad. The worker policy is
  narrower (read-only EC2 + ECR pull).
- **No example uses workload identity / IRSA / managed identity.**
  Where node-side credentials are needed (AWS CCM) they come from
  the instance profile.
- **Equinix Metal** is the only example that has to surface a
  cloud-API token *inside the cluster*: `examples/pulumi/equinix-metal/main.go`
  passes the EM API token into a Talos config patch so the cluster
  can manage its own VIP (lines around 105–107). That token then
  lives in the machine config — worth noting as a secret-rotation
  surface.
- **Omni** is qualitatively different: cluster membership, machine
  classes, and human/API access are declared via
  `omnictl cluster template sync` and live in Omni rather than IaC
  (`examples/omni/README.md`).

## 2. Talos / Kubernetes RBAC + secret material

### Shared baseline

Every cloud example (and the basic bare-metal example) uses the same
four primitives from the Talos provider:

1. `talos_machine_secrets` — generates the cluster PKI (etcd CA,
   Kubernetes CA, machine CA, bootstrap tokens) into Terraform state.
2. `data "talos_machine_configuration"` for `controlplane` and
   `worker` — embeds those secrets into per-node machine config.
3. `data "talos_client_configuration"` — produces the talosconfig that
   `talosctl` uses (admin cert + key + CA, endpoints list).
4. `data "talos_cluster_kubeconfig"` — produces an admin kubeconfig
   (cluster-admin cert + key + CA) after the cluster bootstraps.

Reference: `examples/terraform/aws/main.tf:308-394`,
`examples/terraform/azure/main.tf:144-226`,
`examples/terraform/hcloud/terraform/main.tf:65-168`.

### Findings

- **Long-lived admin credentials, no rotation hook.** The kubeconfig
  and talosconfig emitted by these data sources contain admin
  certificates with the provider's default validity. No example wires
  up `talos_cluster_kubeconfig` to a rotation schedule, and the
  Terraform state holds the corresponding private keys. Anyone with
  state read access has cluster-admin until the certs expire.
- **State is the secret store.** `talos_machine_secrets` writes PKI
  into Terraform state; none of the examples ship a remote backend
  config (the `terraform { }` blocks are minimal), so the README
  assumes the operator configures their own backend with encryption.
  This is fine but worth flagging.
- **Hand-rolled PKI outlier.** `examples/terraform/advanced/`
  generates etcd and Kubernetes PKI directly with `tls_private_key`
  / `tls_self_signed_cert`, then assembles a kubeconfig YAML for the
  `system:masters` user inline. This diverges from the
  provider-managed pattern used everywhere else and reproduces logic
  that the Talos provider already handles. A future ADR could
  consolidate.
- **In-cluster RBAC sample.** The AWS example ships
  `examples/terraform/aws/manifests/ccm.yaml`, which defines a
  `ServiceAccount`, `ClusterRole`, and `ClusterRoleBinding` for the
  AWS cloud controller manager. Its `ClusterRole` is necessarily
  broad (nodes, services, endpoints, events). It is the *only*
  in-tree RBAC in the repo and is referenced by URL from the
  control-plane machine-config patch
  (`examples/terraform/aws/main.tf:10-19`) — meaning operators
  consuming this example pull RBAC from the upstream main branch at
  apply time. Pinning that URL to a tag would be a small hardening.
- **Omni's delegated model.** `examples/omni/infra/patches/cilium.yaml`
  (and the sibling `argocd.yaml`, `monitoring.yaml`, `cni.yaml`,
  `gpu-worker-patch.yaml` patches) carry the in-cluster RBAC for
  Cilium, cilium-operator, hubble-relay, hubble-ui, ArgoCD, and the
  monitoring stack. ArgoCD bootstrap pulls from git, so a
  repo-credential `Secret` for ArgoCD is an additional trust boundary
  worth listing alongside the Omni service-account token.

## 3. Network exposure of control planes

The most important table in this review. "K8s API src" / "Talos API
src" mean the source CIDR allowed to reach those ports by the example's
default values.

| Example | K8s API (`:6443`) src | Talos API (`:50000`) src | Endpoint type | Intra-cluster |
|---|---|---|---|---|
| `terraform/aws` | `0.0.0.0/0` (var) | `0.0.0.0/0` (var) | ELB → 3× public subnets across AZs | Cluster SG `all-all` self |
| `terraform/azure` | `0.0.0.0/0` (var) | `0.0.0.0/0` (var) | Public Standard LB | Single subnet |
| `terraform/hcloud` | `0.0.0.0/0` (no var) | `0.0.0.0/0` (no var) | Public LB with `:6443`, `:50000`, `:30011` | Private network 10.0.0.0/24 |
| `terraform/vultr` | public LB, no firewall | public node IPs, no firewall | Public LB on `:6443` | None — no VPC |
| `terraform/equinix-metal` | Reserved VIP, public | Per-device public IPs | VIP `:6443` | `access_private_ipv4` |
| `pulumi/azure` | `*` (i.e. `0.0.0.0/0`) | `*` | Public Standard LB | Subnet 10.0.1.0/24 |
| `pulumi/gcp` | Public global TCP LB; GCP health-check ranges only on the FW | `0.0.0.0/0` (FW rule) | Global TCP LB → CP instance group | Intra-cluster FW between tags |
| `pulumi/equinix-metal` | Public VIP | Public per-device | VIP `:6443` | Mixed public/private |
| `examples/terraform/basic`, `examples/terraform/advanced` | local libvirt | local libvirt | Node IPs | Local network |
| `examples/omni` | Managed by Omni | n/a (Wireguard via Omni) | Omni control plane | Omni-managed |

Sources:
`examples/terraform/aws/variables.tf:81-91`,
`examples/terraform/aws/main.tf:65-140`;
`examples/terraform/azure/main.tf:28-81`;
`examples/terraform/hcloud/terraform/main.tf:14-60`;
`examples/terraform/vultr/main.tf` (no SG/firewall resources);
`examples/terraform/equinix-metal/main.tf`;
`examples/pulumi/azure/network.go`,
`examples/pulumi/gcp/network.go`,
`examples/pulumi/equinix-metal/main.go`.

### Findings

- **Defaults are open.** AWS and Azure (Terraform) expose variables
  to narrow `kubernetes_api_allowed_cidr` and `talos_api_allowed_cidr`
  but ship with `0.0.0.0/0`. Pulumi Azure hard-codes `*`. An operator
  who copies these examples verbatim ends up with a Talos API
  reachable from the entire internet.
- **No `var.*_allowed_cidr` at all** in `hcloud`, `vultr`, or the
  Equinix Metal examples — there is no narrow-the-source path
  without editing the example.
- **Hetzner load balancer fronts three ports including
  mayastor (`:30011`)** on a public IPv4
  (`examples/terraform/hcloud/terraform/main.tf:55-60`). Mayastor's
  NVMe-oF target on a public LB is worth flagging even if the cluster
  itself is reachable only through this LB.
- **GCP firewall is the best-shaped example.** Health-check ingress
  to `:6443` is limited to GCP's documented health-check ranges
  (`35.191.0.0/16`, `130.211.0.0/22`); a separate rule opens `:50000`
  to `0.0.0.0/0`. The LB itself is internet-facing but the K8s API
  ingress is narrower than every other example.
- **Vultr has no firewall layer.** `main.tf` allocates `main_ip`
  (public) on each instance and a TCP LB on `:6443`; nothing closes
  any other port on the nodes. Talos's default config does not
  expose anything else, but there is no defense-in-depth.

## 4. Omni access model

`examples/omni/` shows a different shape entirely:

- Cluster declared via `omnictl cluster template sync` against
  `examples/omni/infra/cluster-template.yaml`
  (`examples/omni/README.md`), so cluster identity and machine
  membership live in Omni, not in this repo's IaC.
- Workload-proxy feature gates HTTP services behind Omni auth, so
  RBAC for accessing in-cluster apps is delegated to Omni's user
  model rather than `kubectl auth`.
- `examples/omni/infra/patches/cilium.yaml` ships inline RBAC for
  Cilium components and embeds base64 CA material for Hubble.
- ArgoCD bootstrap pulls manifests from a git repository — its
  `Secret` of repo credentials is the trust hinge for everything
  ArgoCD subsequently applies.

The connectivity story is also delegated: there are no firewall
resources in `examples/omni/`; node-to-Omni traffic and operator
access ride over Omni's managed Wireguard mesh.

## 5. Themes worth turning into ADRs

These are not ADRs — they are candidates. Each one is a decision the
repo currently makes implicitly and would benefit from making
explicitly.

1. **Default-deny on Talos and Kubernetes API source CIDRs.**
   Either standardize `*_allowed_cidr` variables across every cloud
   example with a non-`0.0.0.0/0` default (e.g. require the operator
   to set them), or document the open default prominently. Consider
   removing public LB endpoints in favor of operator-side jump hosts
   or Omni for production-shaped examples.
2. **Standardize on provider-managed Talos PKI.** Retire the
   hand-rolled PKI in `examples/terraform/advanced/` and have it use
   `talos_machine_secrets` like every other example, unless there is
   a specific reason to demonstrate manual cert generation.
3. **Document kubeconfig / talosconfig rotation expectations.**
   Today these are long-lived admin credentials emitted to Terraform
   state. The README does not say how an operator is expected to
   rotate them or what happens when the certs expire.
4. **Per-example matrix of "who owns identity."** Surface in the
   top-level README which examples expect cloud IAM (AWS), which
   expect a cloud-API token only (Hetzner, Vultr, Equinix Metal,
   Azure), and which delegate identity wholly to Omni.
5. **Pin RBAC manifests by tag, not `main`.** The AWS control-plane
   patch fetches `manifests/ccm.yaml` from
   `siderolabs/contrib/main`. Pinning to a release tag avoids a
   silent change to in-cluster RBAC at apply time.
6. **Mayastor and other NodePorts on the Hetzner LB.** Decide
   whether `:30011` belongs on a public LB by default. If not,
   gate it behind a variable.
7. **Equinix Metal API token in machine config.** Document the
   blast radius and rotation story for the EM token embedded in
   the cluster's machine config.

## Out of scope (acknowledged)

- No examples were edited.
- No full ADR markdown files were drafted.
- Upstream Talos/Sidero documentation was not consulted; findings
  rely only on what is checked in to this repo.
- Other `edgescaleai/*` repositories were not analyzed — they were
  not reachable from this session.
