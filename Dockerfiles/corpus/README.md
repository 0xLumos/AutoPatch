# AutoPatch evaluation corpus (39 images)

The exact Dockerfiles processed by the published run
(results/ab2yr_bestk_20260813_030142). Build contexts are the
upstream repositories at the pinned commit below; fetch them with
experiments/collect_real_dockerfiles.py or git clone at the SHA.

| image | source repository | pinned commit |
|---|---|---|
| changedetection@0.45.14 | https://github.com/dgtlmoon/changedetection.io | 5119efe4fb3ffa670c8e5b61fd9ebe3f58483a97 |
| croc@v10.0.11 | https://github.com/schollz/croc | 4d11759c21f1e013ec4b80f53b1a44ae42e38729 |
| croc@v10.2.1 | https://github.com/schollz/croc | ba1b5d89d5dc1f902f9c9e7a11eb89944a18cab8 |
| croc@v9.6.9 | https://github.com/schollz/croc | d5e0c8340ba15ab742869cf67e5757d13f7ff661 |
| dolibarr@20.0.3 | https://github.com/Dolibarr/dolibarr | 8548babf32176be46a3bffb4b74674a47b1316a7 |
| etcd@v2.3.0 | https://github.com/etcd-io/etcd | e9ef69008b3390a96698b580c3d0db99509d8ecc |
| etherpad@v1.9.7 | https://github.com/ether/etherpad-lite | f229a482306b43ccb19111fc93f503b71b5f7b81 |
| headscale@v0.22.3 | https://github.com/juanfont/headscale | b01f1f1867136d9b2d7b1392776eb363b482c525 |
| healthchecks@v3.2 | https://github.com/healthchecks/healthchecks | c99b644a228ec664297c172562ec4efc7f25e4ba |
| healthchecks@v3.4 | https://github.com/healthchecks/healthchecks | 17d01ee6e25d73932c22500518cdad6169baa730 |
| healthchecks@v3.9 | https://github.com/healthchecks/healthchecks | 2dd49942595b451780f5b86252bbc17b8c7590ef |
| hugo@v0.122.0 | https://github.com/gohugoio/hugo | b9a03bd59d5f71a529acb3e33f995e0ef332b3aa |
| kubo@v0.26.0 | https://github.com/ipfs/kubo | 1b7d9de13d2e5199dba60a1b85d688b2ce44b736 |
| kubo@v0.29.0 | https://github.com/ipfs/kubo | 8215874649be892adb61d941b4d95525dffb28cd |
| kubo@v0.33.1 | https://github.com/ipfs/kubo | c5a42109c7f2bfd576e99f3059b423f3430a7bb2 |
| lazygit@v0.40.2 | https://github.com/jesseduffield/lazygit | 5e388e21c8ca6aa883dbcbe45c47f6fdd5116815 |
| lazygit@v0.43.1 | https://github.com/jesseduffield/lazygit | 71ad3fac63a3ef3326021837b49e9497d332818b |
| lazygit@v0.45.2 | https://github.com/jesseduffield/lazygit | c03b89227092b852d50015d289a7c6d8c69811c5 |
| mealie@v1.11.0 | https://github.com/mealie-recipes/mealie | a41ad8c6ed968b43e5674ce77785dbdf76f77f57 |
| mealie@v1.2.0 | https://github.com/mealie-recipes/mealie | 42a33cd993b4638f181d4083a7c5d21bf110e4e4 |
| mealie@v2.6.0 | https://github.com/mealie-recipes/mealie | 2d73c703cb8ee192467adb41bbfc1a714a22a819 |
| memos@v0.19.1 | https://github.com/usememos/memos | 374f3f7d9684b8a692e9a82204fb6a9cc61b7984 |
| navidrome@v0.54.4 | https://github.com/navidrome/navidrome | 73ccfbd8399024bffba65cf2dfbb558a3eb6e16f |
| registry@v2.7.0 | https://github.com/distribution/distribution | 1d730e7bbb4eb24c2f22626e3ce8ad7a334d4fb1 |
| restic@v0.16.4 | https://github.com/restic/restic | 9a9cc6dd0d978a8a452ff181558d5856dc217a37 |
| restic@v0.17.0 | https://github.com/restic/restic | 7577c6d1bb11082fbdb311303fd802ab3428cde8 |
| restic@v0.17.3 | https://github.com/restic/restic | 39a6124be558622b0473175af5f8062f3bdca488 |
| sftpgo@v2.5.1 | https://github.com/drakkan/sftpgo | 5b4a1bda2e1b8635390541462b75748c84009668 |
| sftpgo@v2.6.0 | https://github.com/drakkan/sftpgo | 19e9857feae10dd74cd3f3a8af2723a50aba64bd |
| snipe-it@v6.3.0 | https://github.com/snipe/snipe-it | 86c625ed8f5956c8ee75b54578965083742548f1 |
| snipe-it@v7.0.10 | https://github.com/snipe/snipe-it | 39727820330d4abe434b1491ffe55fc1a6308146 |
| snipe-it@v7.1.16 | https://github.com/snipe/snipe-it | bebc1f4d0da3daae7c069b550bae3722a902d787 |
| superset@v2021.41.0 | https://github.com/apache/superset | 828209dfae96a9628b012e4debe8d05f8b50306e |
| tandoor-recipes@1.5.12 | https://github.com/TandoorRecipes/recipes | 2a15d19551c94c04b520090342cc42dd7c71d290 |
| tandoor-recipes@1.5.18 | https://github.com/TandoorRecipes/recipes | af9a95651dc65af5d19aa26d3d7a5b1765a9ca99 |
| tandoor-recipes@1.5.31 | https://github.com/TandoorRecipes/recipes | a0c8b39f0cacc030115ed14683d2a17e0e13f709 |
| victoriametrics@v1.102.1 | https://github.com/VictoriaMetrics/VictoriaMetrics | 996b623585d1945a298d95d9e2ea4f055e2dcd2a |
| victoriametrics@v1.111.0 | https://github.com/VictoriaMetrics/VictoriaMetrics | ee8f852a83e74cd5d18c7acaa60859345ff38b01 |
| wger@2.2 | https://github.com/wger-project/wger | 913969c6106828dc727ee8c94afaeb6bbe90798e |
