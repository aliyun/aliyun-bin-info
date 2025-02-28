pub fn is_random_like_string(s: &str) -> bool {
    let vowels = ['a', 'e', 'i', 'o', 'u'];
    let mut vowel_count = 0;
    let mut total_letter_count = 0;
    let mut special_char_count = 0;

    for c in s.chars() {
        if c.is_alphabetic() {
            total_letter_count += 1;
            if vowels.contains(&(c.to_ascii_lowercase())) {
                vowel_count += 1;
            }
        } else if !c.is_whitespace() && !c.is_numeric() {
            special_char_count += 1;
        }
    }

    let vowel_ratio = if total_letter_count > 0 {
        vowel_count as f64 / total_letter_count as f64
    } else {
        0.0
    };

    let special_char_ratio = if !s.is_empty() {
        special_char_count as f64 / s.len() as f64
    } else {
        0.0
    };

    // 假设如果元音比例小于0.25且特殊字符比例大于0.3，则字符串可能为随机生成
    vowel_ratio < 0.2 || special_char_ratio > 0.2
}

pub fn extract_bin_strings(file_path: &str) -> anyhow::Result<Vec<String>> {
    let config = rust_strings::FileConfig::new(std::path::Path::new(file_path)).
        with_min_length(10);
    let ret = rust_strings::strings(&config);

    let extracted_strings = match ret {
        Ok(s) => s,
        Err(e) => {
            return Err(anyhow::anyhow!("Error extracting strings: {}", e));
        }
    };

    let mut new_strings = Vec::new();
    for (str, _) in extracted_strings {
        let str = str.trim();
        if is_random_like_string(str) {
            continue;
        }
        new_strings.push(str.to_string());
    }
    Ok(new_strings)
}

