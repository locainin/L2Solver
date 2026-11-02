use l2_workbench::{
    derivation::{normalization_work_bound, normalize_message_with_memory},
    job::{MemoryBudget, MemoryClass},
};

fn normalize(input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let budget = MemoryBudget::new(1024 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let output = normalize_message_with_memory(input, &mut lease)?;
    // The charge remains live until the owned result has been copied for this test
    Ok(output.clone())
}

#[test]
fn normalizes_carriage_returns_named_and_numeric_entities() -> Result<(), Box<dyn std::error::Error>>
{
    let input = b"A\r\n&amp; &lt; &gt; &quot; &apos; &#65; &#x42; &#x1F642;";
    let expected = "A\n& < > \" ' A B 🙂".as_bytes();
    assert_eq!(normalize(input)?, expected);
    Ok(())
}

#[test]
fn retains_unsupported_and_malformed_entities() -> Result<(), Box<dyn std::error::Error>> {
    let input = b"&unknown; &#x; &#-3; &amp &#12345678901234567890;";
    assert_eq!(normalize(input)?, input);
    Ok(())
}

#[test]
fn handles_numeric_replacement_and_cr_inside_a_reference() -> Result<(), Box<dyn std::error::Error>>
{
    let input = b"&a\rmp; &#0; &#xD800; &#x80;";
    let output = normalize(input)?;
    assert_eq!(output, "& � � €".as_bytes());
    assert!(output.len() <= input.len());
    assert_eq!(normalization_work_bound(100), Some(800));
    assert_eq!(normalization_work_bound(usize::MAX), None);
    Ok(())
}
