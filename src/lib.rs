// Copyright (c) 2019 Robert Collins. Licensed under the Apache-2.0 license.

#![recursion_limit = "1024"]

#[macro_use]
extern crate nom;

#[macro_use]
extern crate error_chain;

mod errors {
    use std::fmt;

    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {
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

    /// A generic unmodelled syscall:
    /// any name, with any args of any type and any result of any type
    #[derive(Clone, Hash, Eq, Debug, PartialEq)]
    pub struct GenericCall {
        pub call: String,
        /// Not currently modelled, but per-call-type
        pub args: Vec<String>,
        /// Not currently modelled, but per-call-type
        pub result: String,
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
    }

    impl<T: BufRead> Iterator for ParseLines<T> {
        type Item = Line;

        fn next(&mut self) -> Option<Line> {
            let mut line = String::new();
            // TODO: switch to read_until to deal with non-UTF8 strings in the strace.
            let len = self.lines.read_line(&mut line);
            let line = line.as_bytes();
            named!(t, do_parse!(a: take!(10) >> (a)));
            let parsed = nom!(t(&line));

            match parsed {
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            }
        }
    }

    pub fn parse<T: Read>(source: T) -> impl Iterator<Item = Line> {
        ParseLines {
            lines: BufReader::new(source),
        }
    }
}

mod structure {}

#[cfg(test)]
mod tests {
    use crate::raw::{Call, GenericCall, Syscall};
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
                    result: "0".into(),
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
                    result: "0x7fffc415f000".into(),
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
                    result: "?".into(),
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
                    result: "0".into(),
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
                    result: "0x7ffff644d000".into(),
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
                    result: "?".into(),
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
                    result: "?".into(),
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
