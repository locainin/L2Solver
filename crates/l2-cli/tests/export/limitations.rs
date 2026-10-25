use super::{CaseLimitationOrigin, LimitationSpool};
use std::{error::Error, fs::File};

#[test]
fn static_case_limitations_are_counted_once_and_actual_omissions_keep_flow_context()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut spool = LimitationSpool::new(temporary.path())?;
    let static_message = "Capture order and header addresses do not establish ownership, delivery, causality, or malicious intent";
    let actual_omission = "1 capture record was omitted after the retention budget; later absence and event chains are unresolved";

    spool.push_case_limitation(CaseLimitationOrigin::Flow(4), static_message)?;
    spool.push_case_limitation(CaseLimitationOrigin::Flow(7), static_message)?;
    spool.push_case_limitation(
        CaseLimitationOrigin::Cohort("IP-pair cohort flows [4, 7]"),
        static_message,
    )?;
    spool.push_case_limitation(CaseLimitationOrigin::Flow(4), actual_omission)?;
    spool.push_case_limitation(CaseLimitationOrigin::Flow(7), actual_omission)?;

    let mut output = File::create(temporary.path().join("limitations.txt"))?;
    spool.write_to(&mut output)?;
    let report = std::fs::read_to_string(temporary.path().join("limitations.txt"))?;
    spool.remove()?;

    assert_eq!(report.matches(static_message).count(), 1, "{report}");
    assert!(
        report.contains("Case limitation applies to 2 flow Cases and 1 cohort Cases"),
        "{report}"
    );
    assert!(
        report.contains(&format!("- Flow 4: {actual_omission}")),
        "{report}"
    );
    assert!(
        report.contains(&format!("- Flow 7: {actual_omission}")),
        "{report}"
    );
    Ok(())
}
