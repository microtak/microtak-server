# Changelog

## [0.2.0](https://github.com/microtak/microtak-server/compare/microtak-server-v0.1.0...microtak-server-v0.2.0) (2026-09-23)


### Features

* add certificate authority and mTLS transport ([ee9dba9](https://github.com/microtak/microtak-server/commit/ee9dba9bee5d642d371dd5c7e87614d09f8763df))
* add device registry and Marti certificate enrollment endpoint ([0a36cc1](https://github.com/microtak/microtak-server/commit/0a36cc1eb4208cd113d3ed3058dc099bbf690858))
* add mission (Data Sync) metadata store and HTTP API ([43048a9](https://github.com/microtak/microtak-server/commit/43048a9acb1131561fc72dab8fcfd2ba9bd66084))
* add optional TOML config file ([3762660](https://github.com/microtak/microtak-server/commit/37626607d0b328f80a091235b34cac7a2df58736))
* assemble full server and make edgetakd functional ([e69f00d](https://github.com/microtak/microtak-server/commit/e69f00d76aa9c1cfb6a66a9dde686568996d8972))
* **backup:** add periodic local + offsite backup ([683f64d](https://github.com/microtak/microtak-server/commit/683f64d035e0de8725f93feb8183e063709fe2d1))
* close TC-MARTI-10 -- mTLS-authenticate the missions API ([83af5fe](https://github.com/microtak/microtak-server/commit/83af5fef16135602122bb56d07bc5906ee6c3126))
* **cot:** model detail sub-elements (contact, GeoChat, addressing) ([8390756](https://github.com/microtak/microtak-server/commit/8390756ff4dcf6c5820c7089cc1d0ac090d8aaaf))
* **deploy:** add Dockerfile, docker-compose.yml, and a Helm chart ([076de19](https://github.com/microtak/microtak-server/commit/076de197dbc891cffbb1701de763899140cb124e))
* initial CoT event model with tests ([0255f96](https://github.com/microtak/microtak-server/commit/0255f9614d9df42a2690a9bd7e2635ac27020955))
* **marti:** enforce identity binding on the missions API ([07d2da8](https://github.com/microtak/microtak-server/commit/07d2da84de78752dc91a1bd12219cf08fc405ded))
* **marti:** implement clientEndPoints backed by live connections ([27ed981](https://github.com/microtak/microtak-server/commit/27ed981c0792ea83dcc75ab99427a60b45b9f239))
* **marti:** implement DataSync file content storage ([aab81a7](https://github.com/microtak/microtak-server/commit/aab81a74051f32376e3769d575bbe18391a1fe87))
* persist CA, device registry, and mission store across restarts ([e76261e](https://github.com/microtak/microtak-server/commit/e76261ec78853e93e89652e97d63770982da1622))
* **transport:** add CoT stream decoder and plain-TCP relay ([6bb39a3](https://github.com/microtak/microtak-server/commit/6bb39a3197e2680a4e7a908307f2e3834629e90d))
* **transport:** route GeoChat individual and team addressing ([4be1706](https://github.com/microtak/microtak-server/commit/4be17065f8955a4c6dfe108e179218c328973eab))
* **transport:** wire device registry into mTLS transport ([e7a34be](https://github.com/microtak/microtak-server/commit/e7a34be5d932c5664ed5c52398504d0a6a21ab4e))


### Bug Fixes

* **transport:** share one broadcast bus between plain-TCP and mTLS relays ([95a076d](https://github.com/microtak/microtak-server/commit/95a076d5dbc87d3829b4854a3111ffdc22e382d9))


### Refactoring

* **deploy:** rename Docker/Helm artifacts to MicroTAK ([dba6005](https://github.com/microtak/microtak-server/commit/dba60054619f1a7485b8aac6dd8461c87d7be9d8))
* **marti:** generalize enrollment's HTTP listener ([4b1d412](https://github.com/microtak/microtak-server/commit/4b1d412763a1d0a31bea226c9ed2ce162992fe76))
* persist device registry and mission store as event logs ([37d4864](https://github.com/microtak/microtak-server/commit/37d4864989cad69cc4a23b74141dcf5774530ce1))
* prepare pki and enrollment for full server assembly ([210765e](https://github.com/microtak/microtak-server/commit/210765e1daa5f9b59e1968e1c4276ad33fd70578))
* rename project from EdgeTAK to MicroTAK (microtak-server) ([e351ef7](https://github.com/microtak/microtak-server/commit/e351ef7536d7c6f324027cbcc7c40059171d57ef))
* share CN extraction, inject PeerIdentity into Marti API requests ([45cb890](https://github.com/microtak/microtak-server/commit/45cb89011f1d4c26d68d668f9ef8eef34e9c4120))


### Documentation

* add architecture and test-plan documentation ([a63e0e9](https://github.com/microtak/microtak-server/commit/a63e0e9a827028f2e75ed4432a18a4fb18461c33))
* document app assembly, hub fix, and E2E suite ([4c72e4e](https://github.com/microtak/microtak-server/commit/4c72e4ecbd9c80026b0a82497478a8c26a01cefb))
* document mission (Data Sync) API and its unauthenticated-HTTP gap ([7088f6b](https://github.com/microtak/microtak-server/commit/7088f6bab45a364ea21d5be909a9696c0cbdc5e3))
* log user/device mgmt, backup, packaging, and web client roadmap items ([ab575bb](https://github.com/microtak/microtak-server/commit/ab575bbaef8229645cb77bf4655d0db89f2fab01))
* mark transport/TLS/enrollment test cases as implemented ([04cfd46](https://github.com/microtak/microtak-server/commit/04cfd4680a0a9e749cd37e6971fe16063669dde8))
* record backup implementation and add TEST-PLAN §14 ([2e7f148](https://github.com/microtak/microtak-server/commit/2e7f148e4bf3bc5ae108f17941d1d8dfd1d1c428))
* record clientEndPoints (TC-MARTI-09) closure ([03bc60a](https://github.com/microtak/microtak-server/commit/03bc60ab273cfc20c57496f5faf6f6ba6433892a))
* record DataSync content storage (TC-MARTI-07/08) closure ([bdcbd1a](https://github.com/microtak/microtak-server/commit/bdcbd1a1cc8da68a9c3ce29c1c34aaf691ab1538))
* record microtak-server/microtak-sync/microtak-node project split ([fdcb4fd](https://github.com/microtak/microtak-server/commit/fdcb4fd2c3a254719a879e4fe58976aa13b0f60e))
* record persistence, config file, and Reticulum mesh-sync research finding ([8ad495c](https://github.com/microtak/microtak-server/commit/8ad495c32f19e1ed8d7e7befc419478a50e9e141))
* record radio/protocol bridge integration pattern decision ([98bf662](https://github.com/microtak/microtak-server/commit/98bf662ce4bce4cc28c0b4de34d69c36d8819069))
* record TC-MARTI-10 closure (missions API now mTLS-authenticated) ([1b3c03b](https://github.com/microtak/microtak-server/commit/1b3c03ba33b4c5c9a3376cb6b853e2724299f4c9))
* record test-suite red-team review findings ([8077037](https://github.com/microtak/microtak-server/commit/8077037c59f7a5253e268433ee19c341839a4ccb))
* resolve the Reticulum Rust-integration open question ([5bf1b40](https://github.com/microtak/microtak-server/commit/5bf1b403852be83262ff7bcadc97cb460710a816))
* update test plan for registry/enrollment, deprioritize web client ([223dcab](https://github.com/microtak/microtak-server/commit/223dcab8f5c0311bb3baf5c7a9ad356776ae7080))
