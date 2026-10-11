//! `new Date(string).getTime()` as V8 implements it (dateparser.cc): an ES5 ISO-8601
//! pass, then the legacy tokenizer for everything else. Local time is UTC (the
//! container's TZ, as for the upstream Node image). Returns unix ms or None (NaN).

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    // MakeDay with month overflow handled by caller; days since 1970-01-01.
    let y = y + (m - 1).div_euclid(12);
    let m = (m - 1).rem_euclid(12) + 1;
    let (y2, m2) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468 + (d - 1)
}

fn make_time(y: i64, mon: i64, d: i64, h: i64, mi: i64, s: i64, ms: i64, offset_min: i64) -> Option<i64> {
    let t = days_from_civil(y, mon, d) * 86_400_000 + h * 3_600_000 + mi * 60_000 + s * 1000 + ms - offset_min * 60_000;
    // ECMAScript time value range
    (t.abs() <= 8_640_000_000_000_000).then_some(t)
}

pub fn parse(input: &str) -> Option<i64> {
    let s = input.trim_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}');
    if s.is_empty() {
        return None;
    }
    match parse_es5(s) {
        Es5::Done(v) => v,
        Es5::Legacy => parse_legacy(s),
    }
}

enum Es5 {
    Done(Option<i64>),
    Legacy,
}

fn take_digits(b: &[u8], i: &mut usize, n: usize) -> Option<i64> {
    if *i + n > b.len() || !b[*i..*i + n].iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v = std::str::from_utf8(&b[*i..*i + n]).ok()?.parse().ok()?;
    *i += n;
    Some(v)
}

/// ES5 15.9.1.15 format. Falls back to legacy when the string does not start like ISO
/// or (without a `T`) carries extra text after the date.
fn parse_es5(s: &str) -> Es5 {
    let b = s.as_bytes();
    let mut i = 0;
    let year = if b.first() == Some(&b'+') || b.first() == Some(&b'-') {
        let neg = b[0] == b'-';
        i = 1;
        match take_digits(b, &mut i, 6) {
            Some(y) if !(neg && y == 0) => if neg { -y } else { y },
            _ => return Es5::Done(None),
        }
    } else {
        match take_digits(b, &mut i, 4) {
            Some(y) if b.get(4).map(|c| !c.is_ascii_digit()).unwrap_or(true) => y,
            _ => return Es5::Legacy,
        }
    };
    let (mut month, mut day) = (1, 1);
    if b.get(i) == Some(&b'-') {
        i += 1;
        month = match take_digits(b, &mut i, 2) {
            Some(m) => m,
            None => return Es5::Legacy,
        };
        if b.get(i) == Some(&b'-') {
            i += 1;
            day = match take_digits(b, &mut i, 2) {
                Some(d) => d,
                None => return Es5::Legacy,
            };
        }
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Es5::Done(None);
    }
    if i == b.len() {
        // Date-only forms are UTC.
        return Es5::Done(make_time(year, month, day, 0, 0, 0, 0, 0));
    }
    if b[i] != b'T' {
        // e.g. "2026-10-10 10:00": V8 continues with the legacy parser.
        return Es5::Legacy;
    }
    i += 1;
    // After 'T' the remainder must be valid ES5.
    let Some(h) = take_digits(b, &mut i, 2) else { return Es5::Done(None) };
    if b.get(i) != Some(&b':') {
        return Es5::Done(None);
    }
    i += 1;
    let Some(mi) = take_digits(b, &mut i, 2) else { return Es5::Done(None) };
    let (mut sec, mut ms) = (0, 0);
    if b.get(i) == Some(&b':') {
        i += 1;
        let Some(sv) = take_digits(b, &mut i, 2) else { return Es5::Done(None) };
        sec = sv;
        if b.get(i) == Some(&b'.') {
            i += 1;
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == start {
                return Es5::Done(None);
            }
            let frac = &s[start..i];
            let first3: String = frac.chars().chain("000".chars()).take(3).collect();
            ms = first3.parse().unwrap_or(0);
        }
    }
    if h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi > 0 || sec > 0 || ms > 0)) {
        return Es5::Done(None);
    }
    let mut offset = 0; // no offset with time = local = UTC here
    if i < b.len() {
        match b[i] {
            b'Z' => i += 1,
            b'+' | b'-' => {
                let sign = if b[i] == b'-' { -1 } else { 1 };
                i += 1;
                let Some(oh) = take_digits(b, &mut i, 2) else { return Es5::Done(None) };
                if b.get(i) == Some(&b':') {
                    i += 1;
                }
                let Some(om) = take_digits(b, &mut i, 2) else { return Es5::Done(None) };
                if oh > 23 || om > 59 {
                    return Es5::Done(None);
                }
                offset = sign * (oh * 60 + om);
            }
            _ => return Es5::Done(None),
        }
    }
    if i != b.len() {
        return Es5::Done(None);
    }
    Es5::Done(make_time(year, month, day, h, mi, sec, ms, offset))
}

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(i64, usize),
    Word(String),
    Sym(char),
    Space,
}

fn tokenize(s: &str) -> Vec<Tok> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = vec![];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_digit() {
            let st = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let digits: String = chars[st..i].iter().collect();
            out.push(Tok::Num(digits.parse::<i64>().unwrap_or(i64::MAX), i - st));
        } else if c.is_alphabetic() {
            let st = i;
            while i < chars.len() && chars[i].is_alphabetic() {
                i += 1;
            }
            out.push(Tok::Word(chars[st..i].iter().collect::<String>().to_lowercase()));
        } else if c == '(' {
            // Parenthesised text is skipped (nesting allowed).
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '(' {
                    depth += 1;
                } else if chars[i] == ')' {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
        } else if c.is_whitespace() {
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            out.push(Tok::Space);
        } else {
            out.push(Tok::Sym(c));
            i += 1;
        }
    }
    out
}

/// V8 legacy (non-ISO) date parsing.
fn parse_legacy(s: &str) -> Option<i64> {
    let toks = tokenize(s);
    let mut day_nums: Vec<i64> = vec![];
    let mut named_month: Option<i64> = None;
    let mut time: Vec<i64> = vec![];
    let mut ms: i64 = 0;
    let mut ampm: Option<bool> = None; // Some(true) = pm
    let mut tz: Option<i64> = None;
    let mut seen_number = false;
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            Tok::Num(n, len) => {
                seen_number = true;
                let next = toks.get(i + 1);
                if next == Some(&Tok::Sym(':')) || (matches!(next, Some(Tok::Sym('.'))) && !time.is_empty() && time.len() < 3 && false) {
                    if time.len() >= 3 {
                        return None;
                    }
                    time.push(*n);
                    i += 2;
                    continue;
                }
                if !time.is_empty() && time.len() < 3 && toks.get(i.wrapping_sub(1)) == Some(&Tok::Sym(':')) {
                    time.push(*n);
                    // optional .ms after seconds
                    if time.len() == 3 && next == Some(&Tok::Sym('.')) {
                        if let Some(Tok::Num(f, flen)) = toks.get(i + 2) {
                            let digits = format!("{:0width$}", f, width = *flen);
                            ms = format!("{}000", digits)[..3].parse().unwrap_or(0);
                            i += 3;
                            continue;
                        }
                    }
                    i += 1;
                    continue;
                }
                // Timezone offset after a sign.
                if let Some(Tok::Sym(sign @ ('+' | '-'))) = toks.get(i.wrapping_sub(1)) {
                    if tz.is_some() || (!time.is_empty() && day_nums.len() >= 2) || named_month.is_some() && !time.is_empty() {
                        let mins = if *len <= 2 { n * 60 } else { (n / 100) * 60 + n % 100 };
                        tz = Some(if *sign == '-' { -mins } else { mins });
                        i += 1;
                        continue;
                    }
                }
                if *len > 6 || day_nums.len() >= 3 {
                    return None;
                }
                day_nums.push(*n);
                i += 1;
            }
            Tok::Word(w) => {
                if w == "am" || w == "pm" {
                    ampm = Some(w == "pm");
                } else if w == "utc" || w == "gmt" || w == "ut" || w == "z" {
                    tz = Some(0);
                } else if w == "t" && seen_number {
                    // date/time separator
                } else if w.len() >= 3 && MONTHS.contains(&&w[..3]) {
                    named_month = Some(MONTHS.iter().position(|m| *m == &w[..3]).unwrap() as i64 + 1);
                } else if w.len() >= 3 && ["mon", "tue", "wed", "thu", "fri", "sat", "sun"].contains(&&w[..3]) {
                    // weekday names are ignored
                } else if seen_number {
                    return None;
                }
                i += 1;
            }
            Tok::Sym(_) | Tok::Space => i += 1,
        }
    }
    if day_nums.is_empty() && named_month.is_none() {
        return None;
    }
    let fix_year = |y: i64, len_hint: bool| if len_hint && y < 50 { y + 2000 } else if len_hint && y < 100 { y + 1900 } else { y };
    let (year, month, day) = match named_month {
        Some(m) => match day_nums.as_slice() {
            [a, b] => {
                if *a > 31 { (*a, m, *b) } else { (fix_year(*b, *b < 100), m, *a) }
            }
            [y] => (fix_year(*y, *y < 100), m, 1),
            _ => return None,
        },
        None => match day_nums.as_slice() {
            [a, b, c] => {
                if *a > 31 {
                    (*a, *b, *c) // Y/M/D
                } else {
                    (fix_year(*c, *c < 100), *a, *b) // M/D/Y
                }
            }
            [y] if time.is_empty() => (*y, 1, 1),
            _ => return None,
        },
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (mut h, mi, sec) = match time.as_slice() {
        [] => (0, 0, 0),
        [h, m] => (*h, *m, 0),
        [h, m, s] => (*h, *m, *s),
        _ => return None,
    };
    if let Some(pm) = ampm {
        if h > 12 {
            return None;
        }
        h = match (pm, h) {
            (false, 12) => 0,
            (true, 12) => 12,
            (true, x) => x + 12,
            (false, x) => x,
        };
    }
    if h > 24 || mi > 59 || sec > 59 {
        return None;
    }
    make_time(year, month, day, h, mi, sec, ms, tz.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_node_on_corpus() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let input: Vec<String> = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/js_date_corpus.input.json")).unwrap()).unwrap();
        let expected: Vec<Option<i64>> = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/js_date_corpus.expected.json")).unwrap()).unwrap();
        let bad: Vec<String> = input
            .iter()
            .zip(&expected)
            .filter(|(s, e)| super::parse(s) != **e)
            .map(|(s, e)| format!("{s:?}: node {e:?} rust {:?}", super::parse(s)))
            .collect();
        assert!(bad.is_empty(), "{} mismatches:\n{}", bad.len(), bad.join("\n"));
    }
}
