// Copyright (c) 2019 Robert Collins. Licensed under the Apache-2.0 license.

#![recursion_limit = "1024"]

extern crate nom;

#[macro_use]
extern crate error_chain;

pub mod errors {
    use std::fmt;

    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {
        foreign_links {
            Io(::std::io::Error);
        }
        errors {
            NomError(desc: String) {
                description("nom error")
                display("nom error: '{}'", desc)
            }
        }
    }

    // Inspired by https://github.com/Geal/nom/issues/581
    impl<E: fmt::Debug + Clone> From<nom::Err<E>> for Error {
        fn from(error: nom::Err<E>) -> Self {
            let desc = match &error {
                nom::Err::Incomplete(needed) => format!("ran out of bytes: {:?}", needed),
                nom::Err::Error(_) => format!("{:?}", error),
                nom::Err::Failure(_) => format!("{:?}", error),
            };

            Error::from_kind(ErrorKind::NomError(desc))
        }
    }

}

pub mod raw {
    use crate::errors::*;
    use std::io::{BufRead, BufReader, Read};
    use std::time::Duration;

    #[derive(Clone, Hash, Eq, Debug, PartialEq)]
    pub enum CallResult {
        // TODO: convert to u64/pointer width ints perhaps?
        Value(String),
        /// <unfinished ...>
        Unfinished,
        /// ?
        Unknown,
    }

    /// A generic unmodelled syscall:
    /// any name, with any args of any type and any result of any type
    #[derive(Clone, Hash, Eq, Debug, PartialEq)]
    pub struct GenericCall {
        pub call: String,
        /// Not currently modelled, but per-call-type
        pub args: Vec<String>,
        /// Not currently modelled, but per-call-type
        pub result: CallResult,
    }

    /// The syscall or action that happened.
    #[derive(Clone, Hash, Eq, Debug, PartialEq)]
    pub enum Call {
        /// A generic unmodelled syscall was made
        Generic(GenericCall),
        /// The process exited
        Exited(u32),
    }

    #[derive(Clone, Hash, Eq, Debug, PartialEq)]
    pub struct Syscall {
        pub pid: u32,
        pub call: Call,
        /// When the system call started, if known.
        pub start: Option<Duration>,
        /// When the system call finished, if known.
        pub stop: Option<Duration>,
        /// Duration of the system call, if known. Note that duration may be known
        /// without knowing the start and stop as in the following example:
        /// ```2 execve("foo", ["bar"], 0x7fffedc2f180 /* 20 vars */) = 0 <0.005029>```
        pub duration: Option<Duration>,
    }

    impl Syscall {
        pub fn new(
            pid: u32,
            call: Call,
            start: Option<Duration>,
            duration: Option<Duration>,
        ) -> Self {
            Syscall {
                pid,
                call,
                start,
                stop: None,
                duration,
            }
        }

        pub fn set_stop(&mut self) {
            self.stop = self
                .start
                .and_then(|start| self.duration.and_then(|duration| Some(start + duration)));
        }
    }

    pub type Line = Result<Syscall>;

    macro_rules! nom {
        ($expr:expr) => {
            $expr.map_err(Error::from)
        };
    }

    mod parsers {
        use super::{Call, CallResult, Duration, GenericCall};
        use nom::character::complete::digit1;
        use nom::{
            alt, char, complete, delimited, do_parse, escaped, is_a, is_not, map_res, named,
            one_of, opt, recognize, separated_list, tag,
        };
        // Parse a single arg:
        // '6' | '"string\""' | [vector, of things] |
        // '0x1234213 /* 19 vars */ | {...}
        named!(
            parse_arg,
            do_parse!(
                opt!(complete!(tag!(" ")))
                    >> arg: alt!(
                        complete!(recognize!(do_parse!(
                            is_a!("0123456789abcdefx") >> 
                            tag!(" /* ") >> 
                            is_a!("0123456789") >>
                            tag!(" vars */")
                            >> ()
                        ))) |
                        // simple number
                        complete!(is_a!("0123456789abcdefx")) |
                        // It might be a vector ["foo", "bar"]
                        complete!(recognize!(delimited!(char!('['),
                                separated_list!(tag!(","), map_res!(is_not!("],"), std::str::from_utf8)),
                                char!(']')))) |
                            // It might be a string "...."
                        complete!(recognize!(delimited!(char!('"'),
                                escaped!(is_not!("\"\\"), '\\', one_of!("\"n\\0123456789rt")),
                                char!('"')))) |
                        complete!(tag!("NULL")) |
                        complete!(recognize!(
                            is_a!("0123456789_|ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                        ))
                    )
                    >> (arg)
            )
        );
        named!(
                parse_result<&[u8], CallResult>,
                alt!(
                    do_parse!(tag!("?") >> (CallResult::Unknown))
                    | do_parse!(tag!("<unfinished...>") >> (CallResult::Unfinished))
                    | complete!(do_parse!(val: map_res!(recognize!(do_parse!(
                        alt!(tag!("-") | is_a!("0123456789xabcdef")) >> 
                        is_not!(")") >>
                        tag!(")") >>
                        () )), std::str::from_utf8) >> (CallResult::Value(val.into()))))
                    | do_parse!(val: map_res!(is_a!("0123456789xabcdef"), std::str::from_utf8) >> (CallResult::Value(val.into())))
                )
            );

        // Parse the +++ exited with 0 +++ case
        named!(
                parse_exit_event<&[u8], Call>,
                do_parse!(
                    ret: delimited!(tag!("+++ exited with "),
                    map_res!(
                                map_res!(
                                    digit1,
                                    std::str::from_utf8
                                ),
                                |s: &str| s.parse::<u32>()
                            ),
                            tag!(" +++")) >>
                        (Call::Exited(ret)))
        );
        // The sys call fn(...) = xxx
        // Modelled entirely to avoid guessing: either we recognise it or we
        // do not.
        named!(
                pub parse_call<&[u8], Call>,
                complete!(alt!(
                    do_parse!(e: parse_exit_event >> (e))
                    | do_parse!(
                        call: map_res!(is_not!("("), std::str::from_utf8) >>
                        args: delimited!(char!('('),
                              separated_list!(tag!(","), map_res!(parse_arg, std::str::from_utf8)),
                              char!(')')) >>
                        is_a!(" ") >>
                        tag!("= ") >>
                        result: parse_result >>
                        (Call::Generic(GenericCall {call:call.into(), args:args.into_iter().map(|s|s.into()).collect(), result:result.into()})))
                    )
                )
            );

        // The duration ' <...>'
        named!(
                pub parse_duration<&[u8], Option<Duration>>,
                alt!(
                    do_parse!(
                        tag!(" ") >>
                        duration:
                            delimited!(char!('<'),
                                do_parse!(
                                    s: map_res!(
                                        map_res!(
                                            digit1, std::str::from_utf8
                                        ),
                                        |s: &str| s.parse::<u64>()
                                    ) >>
                                    tag!(".") >>
                                    micro: map_res!(
                                        map_res!(
                                            digit1, std::str::from_utf8
                                        ),
                                        |s: &str| s.parse::<u64>()
                                    ) >>
                            ((s * 1_000_000) + micro)
                            ),
                            char!('>')
                        ) >>
                        ( Some(Duration::from_micros(duration)))
                    )
                    |do_parse!((None))
                )
            );

        // The start 20:03:49.406540
        named!(
                pub parse_start<&[u8], Option<Duration>>,
                alt!(
                    do_parse!(
                        hour: map_res!(
                                        map_res!(
                                            digit1, std::str::from_utf8
                                        ),
                                        |s: &str| s.parse::<u64>()
                                    ) >>
                        tag!(":") >>
                        minute: map_res!(
                                        map_res!(
                                            digit1, std::str::from_utf8
                                        ),
                                        |s: &str| s.parse::<u64>()
                                    ) >>
                        tag!(":") >>
                        second: map_res!(
                                        map_res!(
                                            digit1, std::str::from_utf8
                                        ),
                                        |s: &str| s.parse::<u64>()
                                    ) >>
                        tag!(".") >>
                        micros: map_res!(
                                        map_res!(
                                            digit1, std::str::from_utf8
                                        ),
                                        |s: &str| s.parse::<u64>()
                                    ) >>
                        tag!(" ") >>
                        ( Some(Duration::from_micros(
                            ((hour * 60
                               + minute) * 60
                               + second) * 1_000_000
                               + micros
                            )) )
                    )
                    |do_parse!(
                        second: map_res!(
                                        map_res!(
                                            digit1, std::str::from_utf8
                                        ),
                                        |s: &str| s.parse::<u64>()
                                    ) >>
                        tag!(".") >>
                        micros: map_res!(
                                        map_res!(
                                            digit1, std::str::from_utf8
                                        ),
                                        |s: &str| s.parse::<u64>()
                                    ) >>
                        tag!(" ") >>
                        ( Some(Duration::from_micros(second * 1_000_000 + micros)) )
                    )
                    |do_parse!((None))
                )
            );

        #[cfg(test)]
        mod tests {
            use super::*;

            fn parse_inputs<F: Fn(&[u8]) -> nom::IResult<&[u8], &[u8]>>(
                inputs: Vec<&[u8]>,
                parse: F,
            ) {
                for input in inputs.into_iter() {
                    let end = input.len() - 1;
                    let input = &input[..];
                    let expected = &input[1..end];
                    let remainder = &input[end..];
                    let result = parse(input);
                    assert_eq!(result, Ok((remainder, expected)));
                }
            }

            #[test]
            fn parse_arg_int() {
                let input = &b" 2,"[..];

                let result = parse_arg(input);
                assert_eq!(result, Ok((&b","[..], &b"2"[..])));

                let inputs: Vec<&[u8]> = vec![
                    b" 2)", // end of args
                    b" 1,", // not end of args
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_arg_string() {
                let inputs: Vec<&[u8]> = vec![
                    b" \"\"",             // Empty
                    b" \"A\"",            // simple alpha
                    b" \"12\"",           // simple number
                    b" \"\\33(B\\33[m\"", // "\33(B\33[m"
                ];
                for input in inputs.into_iter() {
                    let input = &input[..];
                    let expected = &input[1..];
                    let result = parse_arg(input);
                    assert_eq!(result, Ok((&b""[..], expected)));
                }
            }

            #[test]
            fn parse_arg_vector() {
                // ["./target/debug/rustup", "install", "nightly"],
                let inputs: Vec<&[u8]> = vec![
                    b" [],",            // Empty
                    b" [])",            // Empty
                    b" [\"a\"],",       // 1 element
                    b" [\"a\", \"\"])", // 2 element2
                    b" [1],",           // number elements
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_arg_vars() {
                // 0x7ffff2435d98 /* 19 vars */
                let inputs: Vec<&[u8]> = vec![
                    b" 0x7ffff2435d98 /* 19 vars */,", // not-last
                    b" 0x7ffff2435d98 /* 19 vars */)", // last arg
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[allow(non_snake_case)]
            #[test]

            fn parse_arg_NULL() {
                // NULL
                let inputs: Vec<&[u8]> = vec![
                    // The leading ' ' is weird, but the parser has that outside
                    // the opt and this lets us use the test helper. shrug.
                    b" NULL)",
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]

            fn parse_arg_symbols() {
                let inputs: Vec<&[u8]> = vec![
                    b" F_OK,",
                    b" O_RDONLY|O_CLOEXEC)",
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_call_exited() {
                let input = &b"+++ exited with 0 +++"[..];

                let result = parse_call(input);
                assert_eq!(result, Ok((&b""[..], Call::Exited(0))));
            }

            #[test]
            fn parse_call_write_6() {
                let input = &b"write(2, \"\\33(B\\33[m\", 6) = 6\n"[..];

                let result = parse_call(input);
                assert_eq!(
                    result,
                    Ok((
                        &b"\n"[..],
                        Call::Generic(GenericCall {
                            call: "write".into(),
                            args: vec!["2".into(), "\"\\33(B\\33[m\"".into(), "6".into()],
                            result: CallResult::Value("6".into())
                        })
                    ))
                );
            }

            #[test]
            fn parse_exited() {
                let input = &b"+++ exited with 0 +++"[..];

                let result = parse_exit_event(input);
                assert_eq!(result, Ok((&b""[..], Call::Exited(0))));
            }

            #[test]
            fn result_description1() {
                let input = &b"-1 ENOENT (No such file or directory)"[..];
                let result = parse_result(input);
                assert_eq!(
                    result,
                    Ok((
                        &b""[..],
                        CallResult::Value("-1 ENOENT (No such file or directory)".into())
                    ))
                );
            }

            #[test]
            fn result_description2() {
                let input = &b"0x1 (flags FD_CLOEXEC)"[..];
                let result = parse_result(input);
                assert_eq!(
                    result,
                    Ok((&b""[..], CallResult::Value("0x1 (flags FD_CLOEXEC)".into())))
                );
            }
        }
    }

    struct ParseLines<T: BufRead> {
        lines: T,
        finished: bool,
        last_start: Option<Duration>,
        start_offset: Duration,
    }

    impl<T: BufRead> Iterator for ParseLines<T> {
        type Item = Line;

        fn next(&mut self) -> Option<Line> {
            use nom::character::complete::digit1;
            use nom::{alt, complete, do_parse, map_res, named, opt, tag, terminated};
            use parsers::*;

            if self.finished {
                return None;
            }
            let mut line = String::new();
            // TODO: switch to read_until to deal with non-UTF8 strings in the strace.
            let len = self.lines.read_line(&mut line);
            match len {
                Ok(len) => {
                    if len == 0 {
                        self.finished = true;
                        return None;
                    }
                }
                Err(e) => {
                    self.finished = true;
                    return Some(Err(e.into()));
                }
            }
            let line = line.as_bytes();
            println!("Read {:?}", std::str::from_utf8(line));
            /// string conversion - pending
            // macro_rules! to_str {
            //     ($expr:expr) => {
            //         map_res!($expr, std::str::from_utf8)
            //     };
            // }
            /// The pid "1234 "
            named!(parse_pid<&[u8], u32>,
                map_res!(
                    map_res!(
                        terminated!(digit1, tag!(" ")),
                        std::str::from_utf8
                    ), |s: &str| s.parse::<u32>()
                )
            );

            named!(
                parser<&[u8], Syscall>,
                do_parse!(pid: parse_pid  >>
                    start: parse_start >>
                    call: parse_call >>
                    duration: parse_duration >>
                    opt!(complete!(alt!(tag!("\n") | tag!("\r") | tag!("\r\n")))) >>
                    (Syscall::new(pid, call, start, duration)))
            );
            let parsed = nom!(parser(&line));

            match parsed {
                Ok((remainder, mut value)) => {
                    if remainder.len() != 0 {
                        Some(Err(ErrorKind::NomError(
                            format!("unused input {:?}", std::str::from_utf8(remainder)).into(),
                        )
                        .into()))
                    } else {
                        println!("parsed: {:?}", value);
                        match value.start {
                            None => (),
                            Some(start) => {
                                match self.last_start {
                                    None => {}
                                    Some(last_start) => {
                                        if last_start > start {
                                            // rollover
                                            // increment our offset by a day
                                            self.start_offset += Duration::from_secs(86400);
                                        }
                                    }
                                }
                                self.last_start = value.start;
                            }
                        }
                        value.start = value.start.map(|start| start + self.start_offset);
                        value.set_stop();
                        Some(Ok(value))
                    }
                }
                Err(e) => Some(Err(e)),
            }
        }
    }

    pub fn parse<T: Read>(source: T) -> impl Iterator<Item = Line> {
        ParseLines {
            lines: BufReader::new(source),
            finished: false,
            last_start: None,
            start_offset: Duration::from_secs(0),
        }
    }
}

mod structure {}

#[cfg(test)]
mod tests {
    use crate::raw::{Call, CallResult, GenericCall, Syscall};
    use std::time::Duration;

    #[test]
    fn durationonly() {
        let strace_content = r#"15860 execve("./target/debug/rustup", ["./target/debug/rustup", "uninstall", "nightly"], 0x7fffedc2f180 /* 20 vars */) = 0 <0.005029>
15860 brk(NULL)                         = 0x7fffc415f000 <0.000034>
15860 exit_group(0)                     = ?
15860 +++ exited with 0 +++
"#.as_bytes();
        let parsed: Vec<super::raw::Line> = super::raw::parse(strace_content).collect();
        let expected: Vec<super::raw::Line> = vec![
            Ok(Syscall {
                pid: 15860,
                call: Call::Generic(GenericCall {
                    call: "execve".into(),
                    args: vec![
                        r#""./target/debug/rustup""#.into(),
                        r#"["./target/debug/rustup", "uninstall", "nightly"]"#.into(),
                        "0x7fffedc2f180 /* 20 vars */".into(),
                    ],
                    result: CallResult::Value("0".into()),
                }),
                start: None,
                stop: None,
                duration: Some(Duration::from_micros(5029)),
            }),
            Ok(Syscall {
                pid: 15860,
                call: Call::Generic(GenericCall {
                    call: "brk".into(),
                    args: vec!["NULL".into()],
                    result: CallResult::Value("0x7fffc415f000".into()),
                }),
                start: None,
                stop: None,
                duration: Some(Duration::from_micros(34)),
            }),
            Ok(Syscall {
                pid: 15860,
                call: Call::Generic(GenericCall {
                    call: "exit_group".into(),
                    args: vec!["0".into()],
                    result: CallResult::Unknown,
                }),
                start: None,
                stop: None,
                duration: None,
            }),
            Ok(Syscall {
                pid: 15860,
                call: Call::Exited(0),
                start: None,
                stop: None,
                duration: None,
            }),
        ];
        assert_eq!(parsed.len(), expected.len());
        for (l, r) in parsed.into_iter().zip(expected.into_iter()) {
            assert_eq!(l.unwrap(), r.unwrap());
        }
    }

    #[test]
    fn datemicroandduration() {
        let strace_content = r#"15873 20:03:49.395909 execve("./target/debug/rustup", ["./target/debug/rustup", "install", "nightly"], 0x7ffff2435d98 /* 19 vars */) = 0 <0.008768>
15873 20:03:49.406540 brk(NULL)         = 0x7ffff644d000 <0.000058>
16135 20:12:50.069441 exit_group(0)     = ?
16135 20:12:50.070014 +++ exited with 0 +++
"#.as_bytes();
        let parsed: Vec<super::raw::Line> = super::raw::parse(strace_content).collect();
        let expected: Vec<super::raw::Line> = vec![
            Ok(Syscall {
                pid: 15873,
                call: Call::Generic(GenericCall {
                    call: "execve".into(),
                    args: vec![
                        r#""./target/debug/rustup""#.into(),
                        r#"["./target/debug/rustup", "install", "nightly"]"#.into(),
                        "0x7ffff2435d98 /* 19 vars */".into(),
                    ],
                    result: CallResult::Value("0".into()),
                }),
                start: Some(Duration::from_micros(
                    49_395909 + (((20 * 60) + 3) * 60 * 1_000000),
                )),
                stop: Some(Duration::from_micros(
                    49_395909 + (((20 * 60) + 3) * 60 * 1_000000) + 8768,
                )),
                duration: Some(Duration::from_micros(8768)),
            }),
            Ok(Syscall {
                pid: 15873,
                call: Call::Generic(GenericCall {
                    call: "brk".into(),
                    args: vec!["NULL".into()],
                    result: CallResult::Value("0x7ffff644d000".into()),
                }),
                start: Some(Duration::from_micros(
                    49_406540 + (((20 * 60) + 3) * 60 * 1_000000),
                )),
                stop: Some(Duration::from_micros(
                    49_406540 + (((20 * 60) + 3) * 60 * 1_000000) + 58,
                )),
                duration: Some(Duration::from_micros(58)),
            }),
            Ok(Syscall {
                pid: 16135,
                call: Call::Generic(GenericCall {
                    call: "exit_group".into(),
                    args: vec!["0".into()],
                    result: CallResult::Unknown,
                }),
                start: Some(Duration::from_micros(
                    50_069441 + (((20 * 60) + 12) * 60 * 1_000000),
                )),
                stop: None,
                duration: None,
            }),
            Ok(Syscall {
                pid: 16135,
                call: Call::Exited(0),
                start: Some(Duration::from_micros(
                    50_070014 + (((20 * 60) + 12) * 60 * 1_000000),
                )),
                stop: None,
                duration: None,
            }),
        ];
        assert_eq!(parsed.len(), expected.len());
        for (l, r) in parsed.into_iter().zip(expected.into_iter()) {
            assert_eq!(l.unwrap(), r.unwrap());
        }
    }

    #[test]
    fn datemicrorollover() {
        let strace_content = r#"1 23:59:59.000000 exit_group(0)     = ?
2 0:0:0.000001 +++ exited with 0 +++ <0.000058>
"#
        .as_bytes();
        let parsed: Vec<super::raw::Line> = super::raw::parse(strace_content).collect();
        let expected: Vec<super::raw::Line> = vec![
            Ok(Syscall {
                pid: 1,
                call: Call::Generic(GenericCall {
                    call: "exit_group".into(),
                    args: vec!["0".into()],
                    result: CallResult::Unknown,
                }),
                start: Some(Duration::from_micros(
                    59_000000 + (((23 * 60) + 59) * 60 * 1_000000),
                )),
                stop: None,
                duration: None,
            }),
            Ok(Syscall {
                pid: 2,
                call: Call::Exited(0),
                start: Some(Duration::from_micros(
                    00_000001 + (((24 * 60) + 0) * 60 * 1_000000),
                )),
                stop: Some(Duration::from_micros(
                    00_000001 + (((24 * 60) + 0) * 60 * 1_000000) + 58,
                )),
                duration: Some(Duration::from_micros(58)),
            }),
        ];
        assert_eq!(parsed.len(), expected.len());
        for (l, r) in parsed.into_iter().zip(expected.into_iter()) {
            assert_eq!(l.unwrap(), r.unwrap());
        }
    }

    #[test]
    fn absmicros() {
        let strace_content = r#"1 1560417690.065275 exit_group(0)     = ?
2 1560417690.082832 +++ exited with 0 +++ <0.000058>
"#
        .as_bytes();
        let parsed: Vec<super::raw::Line> = super::raw::parse(strace_content).collect();
        let expected: Vec<super::raw::Line> = vec![
            Ok(Syscall {
                pid: 1,
                call: Call::Generic(GenericCall {
                    call: "exit_group".into(),
                    args: vec!["0".into()],
                    result: CallResult::Unknown,
                }),
                start: Some(Duration::from_micros(1560417690_065275)),
                stop: None,
                duration: None,
            }),
            Ok(Syscall {
                pid: 2,
                call: Call::Exited(0),
                start: Some(Duration::from_micros(1560417690_082832)),
                stop: Some(Duration::from_micros(1560417690_082832 + 58)),
                duration: Some(Duration::from_micros(58)),
            }),
        ];
        assert_eq!(parsed.len(), expected.len());
        for (l, r) in parsed.into_iter().zip(expected.into_iter()) {
            assert_eq!(l.unwrap(), r.unwrap())
        }
    }
}
