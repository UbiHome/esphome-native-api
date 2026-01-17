const FNV1_OFFSET_BASIS: u32 = 2166136261;
const FNV1_PRIME: u32 = 16777619;

fn to_snake_case_char(c: char) -> char {
    if c == ' ' {
        '_'
    } else if c >= 'A' && c <= 'Z' {
        ((c as u8) + (b'a' - b'A')) as char
    } else {
        c
    }
}

fn to_sanitized_char(c: char) -> char {
    // Keep alphanumerics, dashes, underscores; replace others with underscore
    if c == '-'
        || c == '_'
        || (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
    {
        c
    } else {
        '_'
    }
}

pub fn hash_fnv1(name: &String) -> u32 {
    let mut hash = FNV1_OFFSET_BASIS;
    for c in name.chars() {
        hash = hash.wrapping_mul(FNV1_PRIME);
        let processed_char = to_sanitized_char(to_snake_case_char(c));
        hash ^= processed_char as u8 as u32;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fnv1_hash_tests {
        ($($name:ident: $input:expr => $expected:expr;)*) => {
            $(
                #[test]
                fn $name() {
                    let actual = hash_fnv1(&$input.to_string());
                    assert_eq!(
                        actual, $expected,
                        "Hash mismatch for '{}': expected {:#x}, got {:#x}",
                        $input, $expected, actual
                    );
                }
            )*
        };
    }

    fnv1_hash_tests! {
        // Basic strings - hash of sanitize(snake_case(name))
        test_hash_foo: "foo" => 0x408F5E13u32;
        test_hash_foo_uppercase: "Foo" => 0x408F5E13u32; // Same as "foo" (lowercase)
        test_hash_foo_all_caps: "FOO" => 0x408F5E13u32; // Same as "foo" (lowercase)
        // Spaces become underscores
        test_hash_foo_bar_space: "foo bar" => 0x3AE35AA1u32; // transforms to "foo_bar"
        test_hash_foo_bar_space_caps: "Foo Bar" => 0x3AE35AA1u32; // Same (lowercase + underscore)
        // Already snake_case
        test_hash_foo_bar_underscore: "foo_bar" => 0x3AE35AA1u32;
        // Special chars become underscores
        test_hash_foo_bar_exclamation: "foo!bar" => 0x3AE35AA1u32; // Transforms to "foo_bar"
        test_hash_foo_bar_at: "foo@bar" => 0x3AE35AA1u32; // Transforms to "foo_bar"
        // Hyphens are preserved
        test_hash_foo_bar_hyphen: "foo-bar" => 0x438B12E3u32;
        // Numbers are preserved
        test_hash_foo123: "foo123" => 0xF3B0067Du32;
        // Empty string
        test_hash_empty: "" => 0x811C9DC5u32; // FNV1_OFFSET_BASIS (no chars processed)
        // Single char
        test_hash_single_char: "a" => 0x050C5D7Eu32;
        // Mixed case and spaces
        test_hash_my_sensor_name: "My Sensor Name" => 0x2760962Au32; // Transforms to "my_sensor_name"
    }
}
