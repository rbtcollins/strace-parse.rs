// Copyright (c) 2019 Robert Collins. Licensed under the Apache-2.0 license.

#![recursion_limit = "1024"]

extern crate nom;

#[macro_use]
extern crate error_chain;

mod errors {
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

    pub type Line = Result<Syscall>;

    macro_rules! nom {
        ($expr:expr) => {
            $expr.map_err(Error::from)
        };
    }

    struct ParseLines<T: BufRead> {
        lines: T,
        finished: bool,
    }

    mod parsers {
        use super::{Call, CallResult, GenericCall};
        use nom::character::complete::digit1;
        use nom::{
            alt, char, complete, delimited, do_parse, is_a, is_not, map_res, named, opt, recognize,
            separated_list, tag,
        };
        named!(
            parse_arg,
            do_parse!(
                opt!(complete!(tag!(" ")))
                    >> arg: alt!(
                        // It might be a vector ["foo", "bar"]
                        recognize!(delimited!(char!('['),
                                separated_list!(tag!(","), map_res!(is_not!("],"), std::str::from_utf8)),
                                char!(']'))) |
                            // It might be a string "...."
                            is_not!("(),")
                    )
                    >> (arg)
            )
        );
        named!(
                parse_result<&[u8], CallResult>,
                alt!(
                    do_parse!(val: map_res!(is_a!("0123456789xabcdef"), std::str::from_utf8) >> (CallResult::Value(val.into())))
                    | do_parse!(tag!("?") >> (CallResult::Unknown))
                    | do_parse!(tag!("<unfinished...>") >> (CallResult::Unfinished))
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

        #[cfg(test)]
        mod tests {
            use super::*;
            #[test]
            fn parse_call_exited() {
                let input = &b"+++ exited with 0 +++"[..];

                let result = parse_call(input);
                assert_eq!(result, Ok((&b""[..], Call::Exited(0))));
            }

            #[test]
            fn parse_exited() {
                let input = &b"+++ exited with 0 +++"[..];

                let result = parse_exit_event(input);
                assert_eq!(result, Ok((&b""[..], Call::Exited(0))));
            }
        }
    }

    impl<T: BufRead> Iterator for ParseLines<T> {
        type Item = Line;

        fn next(&mut self) -> Option<Line> {
            use nom::character::complete::digit1;
            use nom::{
                alt, char, complete, delimited, do_parse, map_res, named, opt, tag, terminated,
            };
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

            // The duration
            named!(
                parse_duration<&[u8], Option<Duration>>,
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
            named!(
                parser<&[u8], Syscall>,
                do_parse!(pid: parse_pid  >>
                    call: parse_call >>
                    duration: parse_duration >>
                    opt!(complete!(alt!(tag!("\n") | tag!("\r") | tag!("\r\n")))) >>
                    (Syscall {pid, call: call, start: None, stop: None, duration}))
            );
            let parsed = nom!(parser(&line));

            match parsed {
                Ok((remainder, value)) => {
                    if remainder.len() != 0 {
                        Some(Err(ErrorKind::NomError(
                            format!("unused input {:?}", std::str::from_utf8(remainder)).into(),
                        )
                        .into()))
                    } else {
                        println!("parsed: {:?}", value);
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
                pid: 15860,
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
                pid: 15860,
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
2 0:0:0.000001 +++ exited with 0 +++
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
                stop: None,
                duration: None,
            }),
        ];
        assert_eq!(parsed.len(), expected.len());
        for (l, r) in parsed.into_iter().zip(expected.into_iter()) {
            assert_eq!(l.unwrap(), r.unwrap());
        }
    }
}
