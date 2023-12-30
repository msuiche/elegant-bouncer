use elegantbouncer::webp::{is_code_lengths_count_valid, scan_webp_vp8l_file, MAX_DISTANCE_TABLE_SIZE};
use elegantbouncer::jbig2::scan_pdf_jbig2_file;
use elegantbouncer::ttf::scan_ttf_file;

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
}