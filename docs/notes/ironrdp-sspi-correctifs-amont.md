# Note : correctifs amont proposés pour IronRDP et sspi

- **Statut** : textes prêts à déposer par le responsable du projet ; aucun ne bloque le jalon M2.
- **Date** : 2026-11-26
- **Origine** : PR 7 du jalon M2 (`m2/rdp-driver`), [ADR-0019](../adr/0019-driver-rdp-et-passthrough-navigateur.md) section 1 « Correctifs amont », versions épinglées `ironrdp-connector` 0.12.0, `ironrdp-pdu` 0.11.0, `sspi` 0.23.0.

Chaque point décrit le comportement observé dans les sources publiées, ce que nous faisons en attendant, et la proposition. Les textes sont rédigés pour être déposés tels quels (en anglais) dans les dépôts concernés.

## 1. `ironrdp-connector` : rendre la carte à puce optionnelle

**Constat.** `ironrdp-connector` 0.12.0 dépend de `sspi` avec `features = ["scard"]`, sans fonctionnalité Cargo pour s'en passer. Un client qui n'utilise jamais la carte à puce lie quand même `winscard`, `cryptoki` (chargeur PKCS#11 par `libloading`, `dlopen` importé) et `libz-sys` (zlib en C, compilée par `cc`).

**En attendant.** `ostena-rdp` ne construit jamais `Credentials::SmartCard` ; `deny.toml` n'admet ces crates que sous la chaîne `sspi` → `ironrdp-connector`.

**Proposition (texte à déposer).**

> `ironrdp-connector` enables the `scard` feature of `sspi` unconditionally. Clients that never use smart card logon still link `winscard`, `cryptoki` (dynamic loading of PKCS#11 modules) and `libz-sys` (C code built with `cc`). Would you accept a `scard` feature on `ironrdp-connector`, enabled by default to keep the current behaviour, that forwards to `sspi/scard` and gates `Credentials::SmartCard` and the smart card paths of the CredSSP sequence? We can send the pull request.

## 2. `ironrdp-connector` : exposer les drapeaux de la requête X.224 et les `earlyCapabilityFlags`

**Constat.** La requête X.224 est construite avec `RequestFlags::empty()` : impossible de demander `RESTRICTED_ADMIN_MODE_REQUIRED` ([MS-RDPBCGR] 2.2.1.1.1) par la configuration. Le bloc `TS_UD_CS_CORE` reçoit des `earlyCapabilityFlags` calculés par le connecteur (par exemple `RNS_UD_CS_WANT_32BPP_SESSION` dès que la profondeur est de 32 bits), sans moyen de les restreindre à ce que le client traite réellement.

**En attendant.** La garde de séquence d'`ostena-rdp` décode les deux PDU sortantes, les réécrit (protocoles, drapeaux, absence de cookie ; drapeaux hors de sa table retirés) et les réencode avant l'envoi.

**Proposition (texte à déposer).**

> The X.224 Connection Request is always sent with empty request flags, and the `earlyCapabilityFlags` of the Client Core Data are derived internally. A client that needs Restricted Admin (`RESTRICTED_ADMIN_MODE_REQUIRED`) or that must announce only the capabilities it actually handles has to re-encode both PDUs after the connector built them. Would you accept two `Config` fields: `request_flags: nego::RequestFlags` (default empty) and `early_capability_mask: Option<gcc::ClientEarlyCapabilityFlags>` (default `None`: unchanged behaviour; `Some(mask)`: the computed flags are intersected with the mask)?

## 3. `sspi` : `unwrap()` sur des données reçues du KDC

**Constat.** `src/kerberos/client/extractors.rs` (0.23.0), lignes 149 et 158 : `first().unwrap()` sur la liste des types de chiffrement de `PA-ETYPE-INFO2` et sur celle de la partie chiffrée de l'`AS-REP`. Une réponse dont la liste est vide fait paniquer le client.

**En attendant.** La connexion RDP tourne dans sa propre tâche : une panique d'une dépendance coupe la session (`RDP-E099`) sans arrêter l'agent (profil de release avec déroulement de pile). Les KDC sont configurés et joints à l'adresse épinglée seulement, ce qui réduit l'exposition sans la supprimer.

**Proposition (texte à déposer).**

> `extract_encryption_params_from_as_rep` calls `first().unwrap()` on the etype list of `PA-ETYPE-INFO2` and of the AS-REP encrypted part. A KDC response (or a forged one on the path) with an empty sequence makes the client panic. Returning `Error::new(ErrorKind::InvalidToken, ...)` instead would let callers fail the authentication cleanly. We can send the pull request with a test.

## 4. `sspi` : découverte du KDC quand le serveur choisit Kerberos

**Constat.** Dans `negotiate/mod.rs`, quand le serveur choisit Kerberos alors que le protocole courant n'est pas Kerberos, `negotiate_protocol_by_mech_type` crée un client Kerberos avec `kdc_url: None` : le KDC configuré par l'appelant (dans le `KerberosConfig` initial) n'est pas repris, et la découverte (DNS ou variable d'environnement) devient le seul moyen de joindre un KDC. De même, un `NegotiateConfig` avec NTLM et Kerberos admis appelle `detect_kdc_url` à l'initialisation.

**En attendant.** `ostena-rdp` part toujours d'une configuration Kerberos avec `kdc_url` fourni quand Kerberos est admis, et n'admet Kerberos qu'avec un KDC configuré ; le transport KDC refuse tout hôte qui n'est pas un KDC configuré et épinglé par le contrôle de périmètre (pas de découverte, pas de redirection vers un autre KDC).

**Proposition (texte à déposer).**

> When the server selects Kerberos while the current protocol is not Kerberos, `negotiate_protocol_by_mech_type` creates a Kerberos client with `kdc_url: None`, so the KDC configured by the caller is lost and discovery becomes the only way to reach a KDC. Could the Negotiate context keep the KDC URL of the initial `KerberosConfig` (when one was given) and reuse it there, and could discovery be disabled explicitly (for example a `kdc_discovery: bool` in `NegotiateConfig`, default `true`)? Environments that pin their KDCs need a guarantee that no discovery query is issued.

## 5. `sspi` : pas d'API de cache de tickets

**Constat.** `CredSspClient` n'expose ni l'injection d'un TGT obtenu précédemment ni sa récupération : chaque authentification refait l'échange AS puis TGS avec le KDC.

**En attendant.** Le cache de TGT prévu par l'ADR-0019 (section 2) n'est pas réalisé ; le coût est d'environ deux allers-retours vers le KDC par session Kerberos.

**Proposition (texte à déposer).**

> Each CredSSP authentication with Kerberos performs a full AS and TGS exchange. Would you consider an API on the Kerberos client to export the TGT (with its session key, wrapped in a `Secret`) after a successful authentication, and to start a new authentication from a cached TGT, so that callers can implement a bounded in-memory ticket cache?
