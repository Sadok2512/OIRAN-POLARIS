//! 2.23.0 — primitives de réécriture d'identité pour l'amplificateur.
//!
//! Le modèle de l'amplificateur :
//! 1. L'opérateur prend un pcap lab de référence (1 UE) → `UE_src`.
//! 2. Pour chaque `ue_index ∈ [0, K)`, calcule une `SyntheticUe` cible.
//! 3. Pour chaque paquet, copie les bytes du pcap source en remplaçant
//!    les occurrences de l'identité source par l'identité cible.
//!
//! Aucune identité ne « sort » du lab : les cibles sont **toutes
//! synthétiques** (MCC/MNC 001/01 par convention lab). Les tests
//! unitaires ci-dessous vérifient que :
//! - deux `ue_index` distincts donnent des IMSI/MSISDN/IMEI distincts ;
//! - `replace_bytes_all` est idempotent sur une entrée sans match ;
//! - les 15 chiffres d'un IMSI synthétique sont bien tous numériques.

/// Représentation d'un UE synthétique destiné à amplifier un pcap lab.
///
/// Les champs sont des `Vec<u8>` pour être compatibles avec les deux
/// représentations observées dans les protocoles 5G :
///   - encodage TBCD (nibbles) sur NGAP / NAS pour IMSI / IMEI ;
///   - encodage texte « imsi-NNNNN » / « msisdn-NNNNN » dans les URIs SBI.
///
/// Les deux formes sont dérivées du même `ue_index` pour que le pcap
/// amplifié reste **cohérent** (même SUPI observable sur SBI et sur N1/N2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticUe {
    pub ue_index: u32,
    /// IMSI texte 15 chiffres (MCC 001 + MNC 01 + MSIN 10 chiffres
    /// dérivés de `ue_index`). Exemple ue_index=0 → "001010000000000".
    pub imsi: String,
    /// MSISDN texte E.164 12 chiffres préfixé "33" (lab convention).
    pub msisdn: String,
    /// IMEI texte 15 chiffres (TAC 86000000 lab + SN 6 chiffres dérivés
    /// de `ue_index`, Luhn check à la 15e position).
    pub imei: String,
    /// Décalage TEID appliqué aux 4 octets `teid` de toute entête GTP-U
    /// rencontrée. Déterministe par `ue_index`. 0 pour `ue_index=0`.
    pub teid_offset: u32,
    /// Décalage SEID appliqué aux 8 octets PFCP F-SEID / seid header.
    pub seid_offset: u64,
    /// Décalage RAN UE NGAP ID (u40, encodé u64).
    pub ran_ue_ngap_id_offset: u64,
    /// Décalage AMF UE NGAP ID (u40).
    pub amf_ue_ngap_id_offset: u64,
}

/// Construit l'UE synthétique pour `ue_index`. `ue_index=0` est l'UE
/// de référence (pas de décalage : les TEIDs/SEIDs/NGAP IDs du pcap
/// source sont conservés tels quels).
pub fn build_synthetic_ue(ue_index: u32) -> SyntheticUe {
    SyntheticUe {
        ue_index,
        imsi: synthesize_imsi(ue_index),
        msisdn: synthesize_msisdn(ue_index),
        imei: synthesize_imei(ue_index),
        teid_offset: teid_offset(ue_index),
        seid_offset: u64::from(ue_index).wrapping_mul(0x0000_0000_0100_0000),
        ran_ue_ngap_id_offset: u64::from(ue_index).wrapping_mul(0x0000_0001_0000),
        amf_ue_ngap_id_offset: u64::from(ue_index).wrapping_mul(0x0000_0010_0000),
    }
}

/// `ue_index=0` → pas de décalage ; sinon multiplicateur déterministe.
pub fn teid_offset(ue_index: u32) -> u32 {
    ue_index.wrapping_mul(0x0001_0000)
}

/// IMSI synthétique MCC 001 MNC 01 MSIN zero-padded 10 chiffres.
/// Total 15 chiffres : "00101" (5 chars = MCC+MNC) + MSIN 10 chars.
/// Les 10 chiffres MSIN encodent directement `ue_index` en décimal.
pub fn synthesize_imsi(ue_index: u32) -> String {
    format!("00101{:010}", ue_index)
}

/// MSISDN E.164 synthétique "33" + 10 chiffres dérivés de `ue_index`.
pub fn synthesize_msisdn(ue_index: u32) -> String {
    format!("33{:010}", ue_index)
}

/// IMEI synthétique avec Luhn check digit calculé. TAC 86000000 lab.
pub fn synthesize_imei(ue_index: u32) -> String {
    let base = format!("86000000{:06}", ue_index % 1_000_000);
    let check = luhn_check_digit(base.as_bytes());
    // `check` est l'octet ASCII du chiffre (b'0'..=b'9'). On formate via
    // `char` pour éviter que `{check}` ne l'imprime en décimal (valeur
    // ASCII sur 2 chiffres, cassant la longueur à 16).
    format!("{base}{}", check as char)
}

/// Calcul du chiffre de contrôle Luhn pour une chaîne de 14 chiffres.
fn luhn_check_digit(digits: &[u8]) -> u8 {
    let mut sum = 0u32;
    let mut double = true; // position de droite (= position 15e - digits[i] en partant de la fin) ; on itère en reverse
    for digit in digits.iter().rev() {
        if !digit.is_ascii_digit() {
            return b'0';
        }
        let mut d = (digit - b'0') as u32;
        if double {
            d *= 2;
            if d >= 10 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    let check = (10 - (sum % 10)) % 10;
    b'0' + check as u8
}

/// Remplace toutes les occurrences `needle` par `replacement` dans
/// `haystack`. Nécessite `needle.len() == replacement.len()` pour
/// préserver les offsets du pcap (la longueur totale est invariante).
/// Renvoie le nombre de remplacements effectués.
pub fn replace_bytes_all(
    haystack: &mut [u8],
    needle: &[u8],
    replacement: &[u8],
) -> usize {
    assert_eq!(
        needle.len(),
        replacement.len(),
        "needle and replacement must have same length to preserve pcap offsets"
    );
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            haystack[i..i + needle.len()].copy_from_slice(replacement);
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_imsi_has_15_digits_and_lab_mcc_mnc() {
        let imsi = synthesize_imsi(201);
        assert_eq!(imsi.len(), 15, "IMSI should be 15 digits");
        assert!(imsi.starts_with("00101"), "lab MCC/MNC 001/01");
        assert!(imsi.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(imsi, "001010000000201");
    }

    #[test]
    fn synthetic_msisdn_has_12_digits_and_lab_prefix() {
        let msisdn = synthesize_msisdn(42);
        assert_eq!(msisdn.len(), 12);
        assert!(msisdn.starts_with("33"));
        assert_eq!(msisdn, "330000000042");
    }

    #[test]
    fn synthetic_imei_has_15_digits_with_valid_luhn_check() {
        let imei = synthesize_imei(1);
        assert_eq!(imei.len(), 15);
        assert!(imei.chars().all(|c| c.is_ascii_digit()));
        // Verify Luhn: remove last digit, recompute, must match.
        let (base, check) = imei.split_at(14);
        let expected_check = luhn_check_digit(base.as_bytes());
        assert_eq!(
            check.as_bytes()[0],
            expected_check,
            "IMEI {imei} has invalid Luhn check digit"
        );
    }

    #[test]
    fn two_distinct_ue_indices_produce_distinct_imsi_msisdn_imei_teid() {
        let a = build_synthetic_ue(5);
        let b = build_synthetic_ue(6);
        assert_ne!(a.imsi, b.imsi);
        assert_ne!(a.msisdn, b.msisdn);
        assert_ne!(a.imei, b.imei);
        assert_ne!(a.teid_offset, b.teid_offset);
        assert_ne!(a.seid_offset, b.seid_offset);
    }

    #[test]
    fn ue_index_zero_yields_no_offset_reference_ue_is_passthrough() {
        let ue = build_synthetic_ue(0);
        assert_eq!(ue.teid_offset, 0);
        assert_eq!(ue.seid_offset, 0);
        assert_eq!(ue.ran_ue_ngap_id_offset, 0);
        assert_eq!(ue.amf_ue_ngap_id_offset, 0);
    }

    #[test]
    fn replace_bytes_all_requires_same_length_preserves_pcap_offsets() {
        // Pattern IMSI texte "001010000000201" → "001010000000202",
        // 15 octets chacun : taille préservée, offsets du pcap invariants.
        let mut buffer = b"user=001010000000201;other=001010000000201;end".to_vec();
        let n = replace_bytes_all(
            &mut buffer,
            b"001010000000201",
            b"001010000000202",
        );
        assert_eq!(n, 2);
        assert!(buffer.windows(15).any(|w| w == b"001010000000202"));
        assert!(!buffer.windows(15).any(|w| w == b"001010000000201"));
    }

    #[test]
    #[should_panic(expected = "same length")]
    fn replace_bytes_all_panics_on_length_mismatch_to_catch_offset_drift() {
        let mut buffer = b"abc".to_vec();
        replace_bytes_all(&mut buffer, b"abc", b"xyzw");
    }

    #[test]
    fn replace_bytes_all_zero_matches_when_needle_absent_is_noop() {
        let mut buffer = b"no match here".to_vec();
        let n = replace_bytes_all(&mut buffer, b"ZZZ", b"AAA");
        assert_eq!(n, 0);
        assert_eq!(buffer, b"no match here");
    }

    #[test]
    fn luhn_check_digit_matches_known_imei_examples() {
        // IMEI "490154203237518" : les 14 premiers chiffres "49015420323751" →
        // check 8. Exemple classique 3GPP TS 23.003.
        let check = luhn_check_digit(b"49015420323751");
        assert_eq!(check, b'8');
    }
}
