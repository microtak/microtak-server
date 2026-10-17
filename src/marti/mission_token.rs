//! Mission tokens, as the official server issues them
//! (`MissionTokenUtils.createMissionToken`, jjwt 0.9.1): an HS256 JWT,
//! header `{"alg":"HS256"}`, claims in this order:
//! `jti` (the token's id), `iat`, `sub` (the token type), `iss` (the
//! server's flow tag -- `""` by default, `CoreConfig` `<flowtag text="">`),
//! `<TYPE>` (the id again), `MISSION_NAME`, `MISSION_GUID`. No `exp`: the
//! mission API never passes an expiry.
//!
//! The official key is the server certificate's private key bytes; ours is
//! a random secret kept in `data_dir/mission-token-key` (owner-only).
//! Clients treat the token as opaque, so only the shape matters to them.

use base64::Engine;
use ring::hmac;

/// `MissionTokenUtils.TokenType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Subscription,
    Invitation,
    Access,
}

impl TokenType {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenType::Subscription => "SUBSCRIPTION",
            TokenType::Invitation => "INVITATION",
            TokenType::Access => "ACCESS",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "SUBSCRIPTION" => Some(TokenType::Subscription),
            "INVITATION" => Some(TokenType::Invitation),
            "ACCESS" => Some(TokenType::Access),
            _ => None,
        }
    }
}

/// What a valid token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissionClaims {
    pub id: String,
    pub token_type: TokenType,
    pub mission_name: String,
    pub mission_guid: String,
}

pub struct MissionTokenSigner {
    key: hmac::Key,
}

impl MissionTokenSigner {
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        }
    }

    /// A random key (tests; servers use [`Self::load_or_create`]).
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("OS RNG must be available");
        Self::from_secret(&secret)
    }

    /// The server's key from `data_dir/mission-token-key`, created
    /// owner-only on first start.
    pub fn load_or_create(data_dir: &std::path::Path) -> std::io::Result<Self> {
        let path = data_dir.join("mission-token-key");
        match std::fs::read(&path) {
            Ok(secret) if secret.len() >= 32 => Ok(Self::from_secret(&secret)),
            _ => {
                let mut secret = [0u8; 32];
                getrandom::getrandom(&mut secret)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                crate::bootstrap::write_private_file(&path, &secret)?;
                Ok(Self::from_secret(&secret))
            }
        }
    }

    /// A token of `token_type` with id `id` for the mission.
    pub fn create(
        &self,
        id: &str,
        token_type: TokenType,
        mission_name: &str,
        mission_guid: &str,
        now_unix: i64,
    ) -> String {
        let s = |v: &str| serde_json::Value::from(v).to_string();
        let claims = format!(
            r#"{{"jti":{id},"iat":{now_unix},"sub":"{ty}","iss":"","{ty}":{id},"MISSION_NAME":{name},"MISSION_GUID":{guid}}}"#,
            id = s(id),
            ty = token_type.as_str(),
            name = s(mission_name),
            guid = s(mission_guid),
        );
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let signing_input = format!(
            "{}.{}",
            encode(br#"{"alg":"HS256"}"#),
            encode(claims.as_bytes())
        );
        let tag = hmac::sign(&self.key, signing_input.as_bytes());
        format!("{signing_input}.{}", encode(tag.as_ref()))
    }

    /// The claims of a token this server signed; `None` for anything else
    /// (bad signature, malformed, unknown type, missing claims).
    pub fn decode(&self, token: &str) -> Option<MissionClaims> {
        let mut parts = token.split('.');
        let (header, claims, signature) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let signature = b64.decode(signature).ok()?;
        hmac::verify(
            &self.key,
            format!("{header}.{claims}").as_bytes(),
            &signature,
        )
        .ok()?;
        let header: serde_json::Value = serde_json::from_slice(&b64.decode(header).ok()?).ok()?;
        if header["alg"] != "HS256" {
            return None;
        }
        let claims: serde_json::Value = serde_json::from_slice(&b64.decode(claims).ok()?).ok()?;
        let token_type = TokenType::parse(claims["sub"].as_str()?)?;
        Some(MissionClaims {
            id: claims[token_type.as_str()].as_str()?.to_string(),
            token_type,
            mission_name: claims["MISSION_NAME"].as_str()?.to_string(),
            mission_guid: claims["MISSION_GUID"].as_str()?.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(token: &str, n: usize) -> String {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').nth(n).unwrap())
            .unwrap();
        String::from_utf8(raw).unwrap()
    }

    /// The official shape: jjwt's `{"alg":"HS256"}` header and the claims
    /// in `createMissionToken`'s order, with the empty default flow tag.
    #[test]
    fn tokens_have_the_official_shape() {
        let signer = MissionTokenSigner::generate();
        let token = signer.create(
            "sub-1",
            TokenType::Subscription,
            "Ops",
            "6f1c-guid",
            1_760_000_000,
        );
        assert_eq!(segment(&token, 0), r#"{"alg":"HS256"}"#);
        assert_eq!(
            segment(&token, 1),
            r#"{"jti":"sub-1","iat":1760000000,"sub":"SUBSCRIPTION","iss":"","SUBSCRIPTION":"sub-1","MISSION_NAME":"Ops","MISSION_GUID":"6f1c-guid"}"#
        );
    }

    #[test]
    fn a_token_decodes_to_its_claims() {
        let signer = MissionTokenSigner::generate();
        for token_type in [
            TokenType::Subscription,
            TokenType::Invitation,
            TokenType::Access,
        ] {
            let token = signer.create("id-9", token_type, "Name \"quoted\"", "g-1", 0);
            assert_eq!(
                signer.decode(&token),
                Some(MissionClaims {
                    id: "id-9".into(),
                    token_type,
                    mission_name: "Name \"quoted\"".into(),
                    mission_guid: "g-1".into(),
                })
            );
        }
    }

    #[test]
    fn tokens_from_another_key_or_tampered_are_rejected() {
        let signer = MissionTokenSigner::generate();
        let other = MissionTokenSigner::generate();
        let token = other.create("x", TokenType::Access, "Ops", "g", 0);
        assert_eq!(signer.decode(&token), None);

        let mine = signer.create("x", TokenType::Access, "Ops", "g", 0);
        let mut parts: Vec<String> = mine.split('.').map(String::from).collect();
        parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"jti":"x","iat":0,"sub":"ACCESS","iss":"","ACCESS":"x","MISSION_NAME":"Other","MISSION_GUID":"g"}"#);
        assert_eq!(
            signer.decode(&parts.join(".")),
            None,
            "claims changed after signing"
        );
        assert_eq!(signer.decode("not-a-token"), None);
    }

    #[test]
    fn the_key_is_persisted_owner_only() {
        let dir = std::env::temp_dir().join(format!("microtak-mission-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = MissionTokenSigner::load_or_create(&dir).unwrap();
        let token = first.create("x", TokenType::Access, "Ops", "g", 0);
        let again = MissionTokenSigner::load_or_create(&dir).unwrap();
        assert!(again.decode(&token).is_some(), "same key after a restart");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("mission-token-key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
