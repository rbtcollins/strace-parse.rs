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

    use std::cell::Cell;
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::time::Duration;

    #[derive(Clone, Hash, Eq, Debug, PartialEq)]
    pub enum CallResult {
        // TODO: convert to u64/pointer width ints perhaps?
        Value(String),
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
        /// An incomplete call
        Unfinished(String),
        /// A resumed call
        Resumed(String),
        /// The process exited
        Exited(u32),
        /// The process was signalled
        Signalled(String),
    }

    #[derive(Clone, Hash, Eq, Debug, PartialEq)]
    pub struct Syscall {
        pub pid: u32,
        /// When the system call started, if known.
        pub start: Option<Duration>,
        pub call: Call,
        /// When the system call finished_reading, if known. (always inferred from
        /// start+ duration).
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

    pub mod parsers {
        /// The use of nom is not part of the contract of strace-parse; this is
        /// solely public to permit the implementation to be well separated
        /// internally.
        use super::{Call, CallResult, Duration, GenericCall, Syscall};
        use crate::errors::*;
        use nom::character::complete::digit1;
        use nom::character::is_space;
        use nom::{
            alt, char, complete, delimited, do_parse, escaped, is_a, is_not, map_res, named,
            one_of, opt, recognize, separated_list, tag, take_until1, take_while, terminated,
            tuple, AsChar, InputTakeAtPosition,
        };

        pub fn symbol1<'a, E: nom::error::ParseError<&'a [u8]>>(
            input: &'a [u8],
        ) -> nom::IResult<&'a [u8], &'a [u8], E> {
            input.split_at_position1_complete(
                |item| !(item.is_alphanum() || item == b'_'),
                nom::error::ErrorKind::Alpha,
            )
        }

        named!(
            parse_term,
            alt!(
                complete!(recognize!(do_parse!(
                    symbol1
                        >> delimited!(
                            char!('('),
                            separated_list!(tag!(","), parse_arg),
                            char!(')')
                        )
                        >> ()
                ))) | complete!(recognize!(is_a!(
                    "0123456789_|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz->*"
                )))
            )
        );

        named!(
            parse_op,
            recognize!(alt!(
                complete!(tag!("&&")) | complete!(tag!("||")) | complete!(tag!("=="))
            ))
        );

        named!(
            parse_expr<&[u8], &[u8]>,
            alt!(
                // todo: make recursive for arbitrary length exprs
                recognize!(complete!(tuple!(
                    parse_term,
                    tag!(" "),
                    parse_op,
                    tag!(" "),
                    parse_term,
                    tag!(" "),
                    parse_op,
                    tag!(" "),
                    parse_term
                    ))) |
                complete!(parse_term)
            )
        );

        // Parse a single arg:
        // '6' | '"string\""' | [vector, of things] |
        // '0x1234213 /* 19 vars */ | NULL | F_OK |
        // {..., ...}
        // {arg}
        // foo && bar
        // foo || bar
        // foo == bar
        named!(
            parse_arg,
            do_parse!(
                opt!(complete!(take_while!(is_space)))
                    >> r: recognize!(do_parse!(
                        opt!(complete!(terminated!(symbol1, tag!("="))))
                            >> opt!(complete!(tag!("&")))
                            >> arg: alt!(
                                // Commented hex
                                complete!(recognize!(do_parse!(
                            opt!(complete!(is_a!("0123456789abcdefx"))) >>
                            opt!(complete!(tag!(" "))) >>
                            tag!("/* ") >> 
                            opt!(complete!(is_a!("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-:+"))) >>
                            opt!(complete!(tag!("???"))) >>
                            opt!(alt!(complete!(tag!(" vars")) | complete!(tag!(" entries")) )) >>
                            tag!(" */")
                            >> ()
                        ))) |
                        // It might be a vector ["foo", "bar", arg]
                        complete!(recognize!(delimited!(char!('['),
                                separated_list!(tag!(","), parse_arg),
                                char!(']')))) |
                        // It might be a vector ["foo" "bar" arg]
                        complete!(recognize!(delimited!(char!('['),
                                separated_list!(tag!(" "), parse_arg),
                                char!(']')))) |
                        // It might be a string "blah"
                        complete!(recognize!(
                            do_parse!(
                                delimited!(char!('"'),
                                escaped!(is_not!("\"\\"), '\\', one_of!("\"n\\0123456789vrtxf")),
                                char!('"')) >>
                                opt!(tag!("...")) >> ()
                                ))) |
                        // literal NULL
                        complete!(tag!("NULL")) |
                        // It might be a fn(arg)
                        // a symbolic constant or simple number or mapping or
                        // expresions...? (12->34)
                        // argh really need to rework this hole thing bottom up.
                        complete!(recognize!(parse_expr)) |
                        // It might be a struct {"foo", "bar"}
                        complete!(recognize!(delimited!(char!('{'),
                                separated_list!(tag!(","), parse_arg),
                                char!('}')))) |
                        // It might be a struct {foo bar}
                        complete!(recognize!(delimited!(char!('{'),
                                separated_list!(tag!(" "), parse_arg),
                                char!('}')))) |
                        // ellipsis
                        complete!(tag!("..."))
                            )
                            >> (arg)
                    ))
                    >> (r)
            )
        );

        // ? or -(number or hext) then comments.Duration
        // currnetly Unknown is only for standalone ?, ? with comment
        // goes into Value; as results are not fully modelled. Ugh.
        named!(
                parse_result<&[u8], CallResult>,
                alt!(
                     complete!(do_parse!(val: map_res!(recognize!(do_parse!(
                        alt!(tag!("-") | is_a!("?0123456789xabcdef")) >> 
                        is_not!(")") >>
                        tag!(")") >>
                        () )), std::str::from_utf8) >> (CallResult::Value(val.into()))))
                    | do_parse!(val: map_res!(is_a!("0123456789xabcdef"), std::str::from_utf8) >> (CallResult::Value(val.into())))
                    | do_parse!(tag!("?") >> (CallResult::Unknown))
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

        named!(
            eol,
            alt!(complete!(tag!("\r\n")) | complete!(tag!("\n")) | complete!(tag!("\r")))
        );

        //
        named!(
            parse_resumed<&[u8], Call>,
                do_parse!(
                    delimited!(tag!("<... "), symbol1, tag!(" resumed>")) >>
                    opt!(complete!(tag!(" "))) >>
                        l: map_res!(
                            recognize!(tuple!(
                                take_until1!("\n"), // TODO: handle other EOL forms
                                eol
                            )),
                            std::str::from_utf8) >>
                        (Call::Resumed(l.into())))
        );

        // Signall events
        // --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=16135, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
        named!(
            parse_signalled<&[u8], Call>,
            delimited!(tag!("--- "),
            do_parse!(
                symbol1 >>
                v: map_res!(parse_arg, std::str::from_utf8) >>
                (Call::Signalled(v.into()))

            ),tag!(" ---"))
        );

        // The sys call fn(...) = xxx
        // Modelled entirely to avoid guessing: either we recognise it or we
        // do not.
        named!(
                pub parse_call<&[u8], Call>,
                alt!(
                    complete!(do_parse!(e: parse_exit_event >> (e)))
                    // <... epoll_wait resumed> ....
                    // must be before unfinished because of:
                    // 15874 20:12:51.109551 <... epoll_wait resumed> <unfinished ...>) = ?
                    | complete!(parse_resumed)
                    | complete!(do_parse!(
                        l: terminated!(
                                    map_res!(take_until1!(" <unfinished ...>"),
                             std::str::from_utf8),
                                    alt!(complete!(tag!(" <unfinished ...>) = ?")) |
                                         complete!(tag!(" <unfinished ...>")))) >>
                        eol >>
                        (Call::Unfinished(l.into())))
                    )
                    | complete!(parse_signalled)
                    | complete!(do_parse!(
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
                    complete!(do_parse!(
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
                    ))
                    |do_parse!((None))
                )
            );

        // The start 20:03:49.406540
        //           20:03:49.612486
        named!(
                pub parse_start<&[u8], Option<Duration>>,
                opt!(alt!(
                    complete!(do_parse!(
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
                        ( Duration::from_micros(
                            ((hour * 60
                               + minute) * 60
                               + second) * 1_000_000
                               + micros
                            ) )
                    ))
                    |complete!(do_parse!(
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
                        ( Duration::from_micros(second * 1_000_000 + micros) )
                    )
                    )
                    )
                )
            );

        /// The pid "1234 "
        named!(parse_pid<&[u8], u32>,
                complete!(map_res!(
                    map_res!(
                        terminated!(digit1, tag!(" ")),
                        std::str::from_utf8
                    ), |s: &str| s.parse::<u32>()
                ))
            );

        named!(
                pub parser<&[u8], Syscall>,
                do_parse!(pid: parse_pid  >>
                    start: parse_start >>
                    call: parse_call >>
                    duration: parse_duration >>
                    opt!(complete!(eol)) >>
                    (Syscall::new(pid, call, start, duration)))
            );

        named!(
            merge_parser<&[u8], Syscall>,
            do_parse!(
                call: parse_call >>
                duration: parse_duration >>
                opt!(complete!(eol)) >>
                (Syscall::new(0, call, None, duration)))
        );

        /// Merge an unfinished and a resumed syscall.
        /// The syscalls are needed to get the timing data, but the
        /// knowledge of type from the union is embedded, so it can error :/.
        /// If you have ideas on making this nicer let me know.
        /// TODO? move into the higher layer module?
        pub fn merge_resumed(unfinished: Syscall, resumed: Syscall) -> Result<Syscall> {
            if unfinished.pid != resumed.pid {
                return Err("pid mismatch".into());
            }
            let prefix = if let Call::Unfinished(prefix) = unfinished.call {
                prefix
            } else {
                return Err("bad call in unfinished".into());
            };
            let suffix = if let Call::Resumed(suffix) = resumed.call {
                suffix
            } else {
                return Err("bad call in resumed".into());
            };

            let line = prefix + &suffix;
            let (remainder, mut value) = nom!(merge_parser(line.as_bytes()))?;
            if remainder.len() != 0 {
                return Err(ErrorKind::NomError(
                    format!(
                        "unused input {:?} from {:?}",
                        std::str::from_utf8(remainder),
                        &line
                    )
                    .into(),
                )
                .into());
            }
            // Take the start and pid from the original call -
            value.pid = unfinished.pid;
            value.start = unfinished.start;
            value.set_stop();
            Ok(value)
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::raw::Syscall;

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
                    b" 2)",         // end of args
                    b" -1,",        // not end of args, negatives
                    b" 8192*1024)", // Multiplication ?
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_arg_string() {
                let inputs: Vec<&[u8]> = vec![
                    b" \"\"1",             // Empty
                    b" \"A\")",            // simple alpha
                    b" \"12\",",           // simple number
                    b" \"\\33(B\\33[m\")", // "\33(B\33[m"
                    b" \"aqwe\"...,",      // truncated
                    b" \"\\x\")",          // \x - utf8 escape char.
                    b" \"R9\\203\\200\\0\\1\\0\\t\\0\\f\\0\\0\\6static\\trust-lang\\3or\"...,",
                    b" \"\\v\\0\\22\"...,",
                ];
                parse_inputs(inputs, parse_arg);
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
                    b" [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base=\" l\\1\\0\\0\\1\\0\\0\\0\\0\\0\\0\\6static\\trust-lang\\3or\"..., iov_len=38}], msg_iovlen=1, msg_controllen=0, msg_flags=MSG_TRUNC|MSG_DONTWAIT|MSG_FIN|MSG_SYN|MSG_CONFIRM|MSG_ZEROCOPY|MSG_FASTOPEN|0x10000010}, msg_len=38}, {msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base=\"R9\\1\\0\\0\\1\\0\\0\\0\\0\\0\\0\\6static\\trust-lang\\3or\"..., iov_len=38}], msg_iovlen=1, msg_controllen=0, msg_flags=MSG_EOR|MSG_WAITALL|MSG_NOSIGNAL|MSG_MORE|MSG_BATCH|MSG_CMSG_CLOEXEC|0x38a0000}, msg_len=38}],",
                    b" [RTMIN RT_1],", // space delimited
                    b" [28->16],", // Mappings?
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_arg_vars() {
                // 0x7ffff2435d98 /* 19 vars */
                let inputs: Vec<&[u8]> = vec![
                    b" 0x7ffff2435d98 /* 19 vars */,",              // not-last
                    b" 0x7ffff2435d98 /* 19 vars */)",              // last arg
                    b" 0x14 /* NLMSG_??? */,",                      // Enum comment
                    b" 1558857830 /* 2019-05-26T20:03:50+1200 */,", // datestamp comment
                    b" /* 12 entries */,",                          // pure comemnt
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
                    b" st_mode=S_IFREG|0644)",
                    b" st_size=36160,",
                    b" echo,",
                    b" &sin6_addr,",
                    b" WIFEXITED(s) && WEXITSTATUS(s) == 0,",
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_arg_structs() {
                let inputs: Vec<&[u8]> = vec![
                    b" {st_mode=S_IFREG|0644, st_size=36160, ...},",
                    b" {st_mode=S_IFREG|0644, st_size=36160, ...})",
                    b" {u32=4294967295, u64=18446744073709551615},",
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_arg_space_separated_structs() {
                let inputs: Vec<&[u8]> = vec![
                    b" {st_mode=S_IFREG|0644, st_size=36160},",
                    b" {B38400 opost isig icanon echo ...},",
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_nested_structs() {
                let inputs: Vec<&[u8]> = vec![
                    b" {EPOLLIN|EPOLLET, {u32=4294967295, u64=18446744073709551615}},",
                    b" {EPOLLIN|EPOLLET, {u32=4294967295, u64=18446744073709551615}})",
                ];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_fn_calls() {
                let inputs: Vec<&[u8]> = vec![b" st_rdev=makedev(1, 9),"];
                parse_inputs(inputs, parse_arg);
            }

            #[test]
            fn parse_call_exited() {
                let input = &b"+++ exited with 0 +++"[..];

                let result = parse_call(input);
                assert_eq!(result, Ok((&b""[..], Call::Exited(0))));
            }

            #[test]
            fn parse_call_signalled() {
                let input = &b"--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=16135, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---"[..];
                let result = parse_call(input);
                assert_eq!(result, Ok((&b""[..], Call::Signalled("{si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=16135, si_uid=1000, si_status=0, si_utime=0, si_stime=0}".into()))));
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
            fn parse_call_named_arg() {
                let input = &b"write(fred_hollows=2) = 6\n"[..];

                let result = parse_call(input);
                assert_eq!(
                    result,
                    Ok((
                        &b"\n"[..],
                        Call::Generic(GenericCall {
                            call: "write".into(),
                            args: vec!["fred_hollows=2".into()],
                            result: CallResult::Value("6".into())
                        })
                    ))
                );
            }

            // epoll_wait(4,  <unfinished ...>
            // <... epoll_wait resumed> [], 1024, 0) = 0 <0.000542>
            #[test]
            fn parse_call_unfinished_resumed() -> Result<()> {
                let input = &b"epoll_wait(4,  <unfinished ...>\n"[..];
                let result = parse_call(input);
                assert_eq!(
                    result,
                    Ok((&b""[..], Call::Unfinished("epoll_wait(4, ".into())))
                );
                let u = Syscall::new(1, result.unwrap().1, Some(Duration::from_secs(500)), None);

                let input = &b"<... epoll_wait resumed> [], 1024, 0) = 0 <0.000542>\n"[..];
                let result = parse_call(input);
                assert_eq!(
                    result,
                    Ok((
                        &b""[..],
                        Call::Resumed("[], 1024, 0) = 0 <0.000542>\n".into())
                    ))
                );
                let r = Syscall::new(1, result.unwrap().1, None, None);

                let result = merge_resumed(u, r)?;
                assert_eq!(
                    result,
                    Syscall {
                        pid: 1,
                        call: Call::Generic(GenericCall {
                            call: "epoll_wait".into(),
                            args: vec!["4".into(), "[]".into(), "1024".into(), "0".into()],
                            result: CallResult::Value("0".into()),
                        }),
                        start: Some(Duration::from_secs(500)),
                        stop: Some(Duration::from_micros(500_000542)),
                        duration: Some(Duration::from_micros(542))
                    }
                );
                Ok(())
            }

            //
            #[test]
            fn merge_examples() -> Result<()> {
                let (u, r) = (&b"15873 20:12:49.689201 poll([{fd=3, events=POLLIN}, {fd=10, events=POLLIN}], 2, 9997 <unfinished ...>\n"[..],
                &b"15873 20:12:50.070613 <... poll resumed> ) = ? ERESTART_RESTARTBLOCK (Interrupted by signal) <0.380816>\n"[..]);

                let u_p = parser(u)?;
                assert_eq!(&b""[..], u_p.0);
                let r_p = parser(r)?;
                assert_eq!(&b""[..], r_p.0);

                merge_resumed(u_p.1, r_p.1)?;
                Ok(())
            }

            #[test]
            fn parse_call_unfinished() {
                let input = &b"set_robust_list(0x7f1c43b009e0, 24 <unfinished ...>\n"[..];
                let result = parse_call(input);
                assert_eq!(
                    result,
                    Ok((
                        &b""[..],
                        Call::Unfinished("set_robust_list(0x7f1c43b009e0, 24".into())
                    ))
                );
            }

            #[test]
            fn test_parse_resumed() {
                let input = &b"<... epoll_wait resumed> [], 1024, 0) = 0 <0.000542>\n"[..];
                let result = parse_resumed(input);
                assert_eq!(
                    result,
                    Ok((
                        &b""[..],
                        Call::Resumed("[], 1024, 0) = 0 <0.000542>\n".into())
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
                let inputs: Vec<&[u8]> = vec![
                    b"-1 ENOENT (No such file or directory)",
                    b"? ERESTART_RESTARTBLOCK (Interrupted by signal)",
                ];
                for input in inputs.into_iter() {
                    let result = parse_result(input);
                    assert_eq!(
                        result,
                        Ok((
                            &b""[..],
                            CallResult::Value(std::str::from_utf8(input).unwrap().into())
                        ))
                    );
                }
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

            #[test]
            fn result_timestamp() {
                let input = &b"1558857830 (2019-05-26T20:03:50+1200)"[..];
                let result = parse_result(input);
                assert_eq!(
                    result,
                    Ok((
                        &b""[..],
                        CallResult::Value("1558857830 (2019-05-26T20:03:50+1200)".into())
                    ))
                );
            }

            #[test]
            fn test_parse_start() {
                let inputs: Vec<(&[u8], Duration)> =
                    vec![(b"20:03:49.612486 ", Duration::from_micros(72229_612_486))];

                for (input, expected) in inputs.into_iter() {
                    let input = &input[..];
                    let result = parse_start(input);
                    assert_eq!(result, Ok((&b""[..], Some(expected))));
                }
            }

            #[test]
            fn test_parser() {
                let inputs: Vec<&[u8]> = vec![b"1 set(0) <unfinished ...>\n"];

                for input in inputs.into_iter() {
                    let input = &input[..];
                    let result = parser(input);
                    assert_eq!(
                        result,
                        Ok((
                            &b""[..],
                            Syscall {
                                pid: 1,
                                call: Call::Unfinished("set(0)".into()),
                                start: None,
                                stop: None,
                                duration: None
                            }
                        ))
                    );
                }
            }
        }
    }

    type Pool = std::cell::Cell<threadpool::ThreadPool>;
    type SendHandle = Sender<(u64, Line)>;
    type RecvHandle = Receiver<(u64, Line)>;

    struct ParseLines<T: BufRead> {
        lines: T,
        finished_reading: bool,
        last_start: Option<Duration>,
        start_offset: Duration,
        threadpool: Pool,
        serial: u64,
        next_yield: u64,
        send: SendHandle,
        recv: RecvHandle,
        pending_heap: BinaryHeap<Reverse<u64>>,
        pending_lines: HashMap<u64, Line>,
    }

    impl<T: BufRead> ParseLines<T> {
        fn adjust_line(&mut self, parsed: Line) -> Option<Line> {
            self.next_yield += 1;
            return match parsed {
                Ok(mut value) => {
                    //println!("parsed: {:?}", value);
                    match value.start {
                        None => (),
                        Some(start) => {
                            if start < Duration::from_secs(86402) {
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
                            value.start = value.start.map(|start| start + self.start_offset);
                            value.set_stop();
                        }
                    }
                    Some(Ok(value))
                }
                Err(e) => Some(Err(e)),
            };
        }

        fn finish_reading(&mut self) {
            self.finished_reading = true;
            // bit ugly but gets a replacement handle to make
            // the current one close (and let blocking iteration
            // terminate correctly)
            let (send, _recv) = channel();
            std::mem::replace(&mut self.send, send);
        }

        fn dispatch_line(&mut self) -> Result<()> {
            use parsers::*;
            let mut line = String::new();
            // TODO: switch to read_until to deal with non-UTF8 strings in
            // the strace.
            let len = self.lines.read_line(&mut line);
            match len {
                Ok(len) => {
                    if len == 0 {
                        self.finish_reading();
                        return Ok(());
                    }
                }
                Err(e) => {
                    self.finish_reading();
                    return Err(e.into());
                }
            }
            let id = self.serial;
            self.serial += 1;
            let send = self.send.clone();
            self.threadpool.get_mut().execute(move || {
                let line = line.as_bytes();
                let parsed = nom!(parser(&line));
                let result = match parsed {
                    Ok((remainder, value)) => {
                        if remainder.len() != 0 {
                            Err(ErrorKind::NomError(
                                format!("unused input {:?}", std::str::from_utf8(remainder)).into(),
                            )
                            .into())
                        } else {
                            Ok(value)
                        }
                    }
                    Err(e) => {
                        println!("Failed {:?}", std::str::from_utf8(line));
                        Err(e)
                    }
                };
                send.send((id, result)).expect("receiver must not quit");
            });
            Ok(())
        }

        fn dispatch_lines(&mut self) -> Option<Option<Line>> {
            for _ in 1..self.threadpool.get_mut().max_count() {
                if !self.finished_reading {
                    if let Err(e) = self.dispatch_line() {
                        return Some(Some(Err(e)));
                    }
                }
            }
            None
        }
    }

    impl<T: BufRead> Iterator for ParseLines<T> {
        type Item = Line;

        fn next(&mut self) -> Option<Line> {
            // Each line can be parsed separately.
            // next() thus does the following:
            // 0) try to pick up *a* line and submit it
            // 1) look for the next result in the completed cache
            // 2) alternate between iterating completed values
            //    looking for the next result
            // 3) when there is no more input, close the
            //    mpsc input handle to permit blocking reads
            // This isn't free-threading the reads to avoid just bloating all
            // memory all at once; that would be a possible future change.
            if let Some(e) = self.dispatch_lines() {
                return e;
            }

            if let Some(available) = self.pending_heap.peek() {
                if available.0 == self.next_yield {
                    self.pending_heap.pop();
                    let parsed = self.pending_lines.remove(&self.next_yield).unwrap();
                    return self.adjust_line(parsed);
                }
            }

            loop {
                // perhaps the line we want is waiting in the mpsc queue
                for (id, parsed) in self.recv.try_iter() {
                    if id != self.next_yield {
                        // stash this line for later processing
                        self.pending_heap.push(Reverse(id));
                        self.pending_lines.insert(id, parsed);
                        continue;
                    }
                    return self.adjust_line(parsed);
                }
                // but if not, lets send another line for processing, todo: give
                // up CPU when the queue grows (e.g. single core machines)
                if let Some(e) = self.dispatch_lines() {
                    return e;
                }
                if self.finished_reading {
                    // We've finished reading, so there is nothing to do but
                    // wait for the line we want.
                    for (id, parsed) in self.recv.iter() {
                        if id != self.next_yield {
                            // stash this line for later processing
                            self.pending_heap.push(Reverse(id));
                            self.pending_lines.insert(id, parsed);
                            continue;
                        }
                        return self.adjust_line(parsed);
                    }
                    // And if we reach here there are no more lines.
                    return None;
                }
            }
        }
    }

    pub fn parse<T: Read>(source: T) -> impl Iterator<Item = Line> {
        let pool = Cell::new(threadpool::ThreadPool::default());
        let (send, recv) = channel();
        ParseLines {
            lines: BufReader::new(source),
            finished_reading: false,
            last_start: None,
            start_offset: Duration::from_secs(0),
            threadpool: pool,
            serial: 0,
            next_yield: 0,
            send,
            recv,
            pending_heap: BinaryHeap::default(),
            pending_lines: HashMap::default(),
        }
    }

    pub fn parse_with_pool<T: Read>(source: T, threadpool: Pool) -> impl Iterator<Item = Line> {
        let (send, recv) = channel();
        ParseLines {
            lines: BufReader::new(source),
            finished_reading: false,
            last_start: None,
            start_offset: Duration::from_secs(0),
            threadpool,
            serial: 0,
            next_yield: 0,
            send,
            recv,
            pending_heap: BinaryHeap::default(),
            pending_lines: HashMap::default(),
        }
    }
}

pub mod structure {
    use crate::raw::parsers::merge_resumed;
    use crate::raw::{Call, Line, Syscall};

    use std::collections::HashMap;

    struct MergeUnfinished<T: Iterator<Item = Line>> {
        // Underlying iterator
        input: T,
        // unfinished syscalls
        unfinished: HashMap<u32, Syscall>,
    }

    impl<T: Iterator<Item = Line>> MergeUnfinished<T> {
        fn find_one(&self) -> Option<u32> {
            let residue: Vec<(&u32, &Syscall)> = self.unfinished.iter().take(1).collect();
            for (k, _) in residue.into_iter() {
                return Some(*k);
            }
            None
        }
    }

    impl<T: Iterator<Item = Line>> Iterator for MergeUnfinished<T> {
        type Item = Line;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                match self.input.next() {
                    None => {
                        for k in self.find_one() {
                            // Remaining unfinished syscalls - forward as-is
                            let syscall = self.unfinished.remove(&k).unwrap();
                            return Some(Ok(syscall));
                        }
                        return None;
                    }
                    Some(item) => {
                        match item {
                            Err(e) => return Some(Err(e)),
                            Ok(syscall) => {
                                match &syscall.call {
                                    Call::Unfinished(_) => {
                                        if let Some(oldcall) =
                                            self.unfinished.insert(syscall.pid, syscall)
                                        {
                                            panic!(
                                                "double unfinished rainbow {:?} {:?}",
                                                &oldcall,
                                                self.unfinished.get(&oldcall.pid).unwrap()
                                            );
                                        }
                                        continue;
                                    }
                                    Call::Resumed(_) => {
                                        match self.unfinished.remove(&syscall.pid) {
                                            None => {
                                                // resume without unfinished -
                                                // forward as-is
                                                return Some(Ok(syscall));
                                            }
                                            Some(unfinished) => {
                                                return Some(merge_resumed(unfinished, syscall));
                                            }
                                        }
                                    }
                                    _ => {
                                        if self.unfinished.contains_key(&syscall.pid) {
                                            panic!("syscall after unfinished without resume");
                                        }
                                        return Some(Ok(syscall));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn iter_finished<T: Iterator<Item = Line>>(input: T) -> impl Iterator<Item = Line> {
        Box::new(MergeUnfinished {
            input,
            unfinished: HashMap::default(),
        })
    }

    #[cfg(test)]
    mod tests {
        use crate::raw;
        use crate::raw::{Call, CallResult, GenericCall, Syscall};

        use std::time::Duration;

        use super::iter_finished;

        #[test]
        fn test_iter_finished_syscalls() {
            let strace_content = r#"15873 20:12:50.110067 futex(0x7ffff644d58c, FUTEX_WAIT_PRIVATE, 0, {tv_sec=29, tv_nsec=996182600} <unfinished ...>
15874 20:12:50.111078 futex(0x7f1c3c0e4df8, FUTEX_WAKE_PRIVATE, 1) = 1 <0.000037>
15876 20:12:50.111684 <... futex resumed> ) = 0 <540.139763>
15874 20:12:50.112197 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
15876 20:12:50.112686 futex(0x7f1c3c014940, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
15874 20:12:50.113193 <... clock_gettime resumed> {tv_sec=343451, tv_nsec=974375300}) = 0 <0.000527>
15876 20:12:50.113692 <... futex resumed> ) = 0 <0.000514>
15874 20:12:50.114199 clock_gettime(CLOCK_MONOTONIC,  <unfinished ...>
15876 20:12:50.114686 futex(0x7f1c3c0143f0, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>
15874 20:12:50.115252 <... clock_gettime resumed> {tv_sec=343451, tv_nsec=976375200}) = 0 <0.000545>
15876 20:12:50.115759 <... futex resumed> ) = 1 <0.000559>
15879 20:12:51.065041 epoll_wait(4,  <unfinished ...>
15879 20:12:51.109551 <... epoll_wait resumed> <unfinished ...>) = ?
15879 20:12:51.110377 +++ exited with 0 +++
"#.as_bytes();
            let intermediate = raw::parse(strace_content);
            let expected: Vec<raw::Line> = vec![
                Ok(Syscall {
                pid: 15874,
                call: Call::Generic(GenericCall {
                    call:"futex".into(),
                    args:vec!["0x7f1c3c0e4df8".into(), "FUTEX_WAKE_PRIVATE".into(), "1".into()],
                    result:CallResult::Value("1".into())
                }),
                start: Some(Duration::from_micros(72770_111078)),
                stop: Some(Duration::from_micros(72770_111115)),
                duration: Some(Duration::from_micros(37)),
            }),
            Ok(Syscall {
                pid: 15876,
                call: Call::Resumed(") = 0 <540.139763>\n".into()),
                start: Some(Duration::from_micros(72770_111684)),
                stop: None,
                duration: None,
            }),
            Ok(Syscall {
                pid: 15874,
                call: Call::Generic(GenericCall {
                    call:"clock_gettime".into(),
                    args:vec!["CLOCK_MONOTONIC".into(), "{tv_sec=343451, tv_nsec=974375300}".into()],
                    result:CallResult::Value("0".into())
                }),
                start: Some(Duration::from_micros(72770_112197)),
                stop: Some(Duration::from_micros(72770_112724)),
                duration: Some(Duration::from_micros(527)),
            }),
            Ok(Syscall {
                pid: 15876,
                call: Call::Generic(GenericCall { call: "futex".into(), 
                args: vec!["0x7f1c3c014940".into(), "FUTEX_WAKE_PRIVATE".into(), "1".into()], result: CallResult::Value("0".into()) }),
                start: Some(Duration::from_micros(72770_112686)),
                stop: Some(Duration::from_micros(72770_113200)),
                duration: Some(Duration::from_micros(514)),
            }),
            Ok(Syscall {
                pid: 15874,
                call: Call::Generic(GenericCall { call: "clock_gettime".into(), args: vec!["CLOCK_MONOTONIC".into(), "{tv_sec=343451, tv_nsec=976375200}".into()], result: CallResult::Value("0".into()) }),
                start: Some(Duration::from_micros(72770_114199)),
                stop: Some(Duration::from_micros(72770_114744)),
                duration: Some(Duration::from_micros(545)),
            }),
            Ok(Syscall {
                pid: 15876,
                call: Call::Generic(GenericCall { call: "futex".into(), args: vec!["0x7f1c3c0143f0".into(), "FUTEX_WAKE_PRIVATE".into(), "1".into()], result: CallResult::Value("1".into()) }),
                start: Some(Duration::from_micros(72770_114686)),
                stop: Some(Duration::from_micros(72770_115245)),
                duration: Some(Duration::from_micros(559)),
            }),
            Ok(Syscall {
                pid: 15879,
                call: Call::Unfinished("epoll_wait(4,".into()),
                start: Some(Duration::from_micros(72771_065041)),
                stop: None,
                duration: None,
            }),
            Ok(Syscall {
                pid: 15879,
                call: Call::Exited(0),
                start: Some(Duration::from_micros(72771_110377)),
                stop: None,
                duration: None,
            }),
            Ok(Syscall {
                pid: 15873,
                call: Call::Unfinished("futex(0x7ffff644d58c, FUTEX_WAIT_PRIVATE, 0, {tv_sec=29, tv_nsec=996182600}".into()),
                start: Some(Duration::from_micros(72770_110067)),
                stop: None,
                duration: None,
            }),
            ];
            let parsed: Vec<raw::Line> = iter_finished(intermediate).collect();
            assert_eq!(parsed.len(), expected.len());
            for (l, r) in parsed.into_iter().zip(expected.into_iter()) {
                assert_eq!(l.unwrap(), r.unwrap());
            }
        }
    }
}

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
