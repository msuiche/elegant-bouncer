use elegantbouncer::webp::{is_code_lengths_count_valid, scan_webp_vp8l_file, MAX_DISTANCE_TABLE_SIZE};
use elegantbouncer::jbig2::scan_pdf_jbig2_file;
use elegantbouncer::ttf::scan_ttf_file;
use elegantbouncer::dng::scan_dng_file;
use elegantbouncer::heif::{scan_heif_file, HeifCve};

use elegantbouncer::errors::ScanResultStatus;

use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_lengths_count() {
        let evil_array = [0, 1, 1, 1, 1, 1, 0, 0, 0, 11, 5, 1, 10, 4, 2, 2 ];
        let blastpass = is_code_lengths_count_valid(&evil_array.to_vec(), MAX_DISTANCE_TABLE_SIZE);

        assert!(blastpass);
    } 

    #[test]
    fn test_blastpass_sample() {
        let path = Path::new("tests/samples/BLASTPASS.webp");
        let res = scan_webp_vp8l_file(path);

        assert_eq!(res.ok(), Some(ScanResultStatus::StatusMalicious));
    }

    #[test]
    fn test_blastpass_apple_sample() {
        let path = Path::new("tests/samples/replicatevalue_poc.not_.webp");
        let res = scan_webp_vp8l_file(path);

        assert_eq!(res.ok(), Some(ScanResultStatus::StatusMalicious));
    }

    #[test]
    fn test_forcedentry_sample() {
        let path = Path::new("tests/samples/FORCEDENTRY.gif");
        let res = scan_pdf_jbig2_file(path);

        assert_eq!(res.ok(), Some(ScanResultStatus::StatusMalicious));
    }

    #[test]
    fn test_run_ttf() {
        let path = Path::new("tests/samples/07558_CenturyGothic.ttf");
        let res = scan_ttf_file(path);

        assert_eq!(res.ok(), Some(ScanResultStatus::StatusOk));
    }

    #[test]
    fn test_cve_2025_43300_malicious() {
        let path = Path::new("/Users/msuiche/Downloads/IMGP0847_malicious.DNG");
        if !path.exists() {
            return;
        }
        let (status, _cve) = scan_dng_file(path);

        assert_eq!(status, ScanResultStatus::StatusMalicious);
    }

    #[test]
    fn test_cve_2025_43300_benign() {
        let path = Path::new("/Users/msuiche/Downloads/IMGP0847.DNG");
        if !path.exists() {
            return;
        }
        let (status, _cve) = scan_dng_file(path);

        assert_eq!(status, ScanResultStatus::StatusOk);
    }

    // libheif mask image ('mski') defects - CVE-2026-32741 and the 16-bpp underfill.

    #[test]
    fn test_cve_2026_32741_heic_sample() {
        let path = Path::new("tests/samples/CVE-2026-32741.heic");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusMalicious);
        assert_eq!(cve, Some(HeifCve::Cve202632741));
    }

    #[test]
    fn test_cve_2026_32741_avif_sample() {
        let path = Path::new("tests/samples/CVE-2026-32741.avif");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusMalicious);
        assert_eq!(cve, Some(HeifCve::Cve202632741));
    }

    #[test]
    fn test_heif_mask_underfill_sample() {
        let path = Path::new("tests/samples/heif-mask-underfill16.heic");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusMalicious);
        assert_eq!(cve, Some(HeifCve::MaskUninitDisclosure));
    }

    #[test]
    fn test_heif_mask_benign_sample() {
        let path = Path::new("tests/samples/heif-mask-benign.heic");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusOk);
        assert_eq!(cve, None);
    }

    #[test]
    fn test_heif_mask_benign16_sample() {
        // 16 bpp with a complete plane: the underfill heuristic must not fire.
        let path = Path::new("tests/samples/heif-mask-benign16.heic");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusOk);
        assert_eq!(cve, None);
    }

    #[test]
    fn test_heif_scanner_ignores_non_heif() {
        // No 'ftyp' box, so the container is never parsed as HEIF.
        let path = Path::new("tests/samples/BLASTPASS.webp");
        let (status, _cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusOk);
    }

    #[test]
    fn test_heif_finding_details() {
        let path = Path::new("tests/samples/CVE-2026-32741.heic");
        let findings = elegantbouncer::heif::analyze_heif_file(path);

        assert_eq!(findings.len(), 1);
        let mask = findings[0].mask.as_ref().expect("mask geometry");
        assert_eq!((mask.width, mask.height), (64, 64));
        assert_eq!(mask.bits_per_pixel, 8);
        assert_eq!(mask.required_len, 4096);
        assert_eq!(mask.extent_len, 69632);
        // stride == width, so decode_mask_image() takes the single-memcpy branch.
        assert!(mask.full_copy_branch);
        assert!(mask.extent_len > mask.plane_alloc);
    }

    // libheif item graph defects - CVE-2026-84383 (duplicate alpha planes feeding
    // scale_nearest_neighbor) and CVE-2026-32882 (overlay alpha over-read).

    #[test]
    fn test_cve_2026_84383_advisory_poc() {
        // The advisory's exact construction: hvc1 + alpha, an iden item that is
        // itself an alpha with its own 10-bit alpha, and a 128x128 primary.
        let path = Path::new("tests/samples/CVE-2026-84383.heic");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusMalicious);
        assert_eq!(cve, Some(HeifCve::Cve202684383));
    }

    #[test]
    fn test_cve_2026_84383_av1_variant() {
        // Same item graph with av01 items, the variant that reaches the scaler
        // through sharp.
        let path = Path::new("tests/samples/CVE-2026-84383.avif");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusMalicious);
        assert_eq!(cve, Some(HeifCve::Cve202684383));
    }

    #[test]
    fn test_cve_2026_84383_detail_names_both_planes() {
        let path = Path::new("tests/samples/CVE-2026-84383.heic");
        let findings = elegantbouncer::heif::analyze_heif_file(path);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cve, HeifCve::Cve202684383);
        assert_eq!(findings[0].item_id, 3);
        // The second, deeper alpha is what overflows the 8-bit allocation.
        assert!(findings[0].detail.contains("10-bit"));
        assert!(findings[0].detail.contains("8-bit"));
    }

    #[test]
    fn test_heif_single_alpha_benign() {
        // The advisory PoC's own control: one image, one alpha, no iden item.
        let path = Path::new("tests/samples/heif-alpha-benign.heic");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusOk);
        assert_eq!(cve, None);
    }

    #[test]
    fn test_cve_2026_32882_overlay_depth_mismatch() {
        let path = Path::new("tests/samples/CVE-2026-32882.heic");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusMalicious);
        assert_eq!(cve, Some(HeifCve::Cve202632882));
    }

    #[test]
    fn test_heif_overlay_matching_depths_benign() {
        // Same overlay, alpha and colour both 8-bit: the strides agree.
        let path = Path::new("tests/samples/heif-overlay-benign.heic");
        let (status, cve) = scan_heif_file(path);

        assert_eq!(status, ScanResultStatus::StatusOk);
        assert_eq!(cve, None);
    }
}