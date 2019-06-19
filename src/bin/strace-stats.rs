use std::collections::BTreeMap;
use std::env;
use std::time::Duration;

use strace_parse::errors::*;
use strace_parse::raw::Call;

// % time     seconds  usecs/call     calls    errors syscall
// ------ ----------- ----------- --------- --------- ----------------
//   0.00    0.000000           0         8           read
// ...
//   0.00    0.000000           0         1           getrandom
// ------ ----------- ----------- --------- --------- ----------------
// 100.00    0.000000                    99         9 total

#[derive(Debug)]
struct Counter {
    calls: u64,
    duration: Duration,
    // errors:  requires more semantic analyis
}

fn main() -> Result<()> {
    for fname in env::args().skip(1) {
        println!("{:?}", fname);
        let file = std::fs::File::open(fname)?;
        let mut total_time = Duration::from_secs(0);
        let mut calls = BTreeMap::new();
        for event in strace_parse::structure::iter_finished(strace_parse::raw::parse(file)) {
            let event = event?;
            let duration = event
                .duration
                .map_or(Duration::from_secs(0), |duration| duration);
            total_time += duration;
            let call_name = match event.call {
                Call::Generic(syscall) => Some(syscall.call),
                // TODO:? pick out syscall names from unfinished calls?
                // TODO: stats on signals and exits and forks?
                _ => None,
            };
            if let Some(name) = call_name {
                // common case
                let mut counter = calls.get_mut(&name);
                if let None = counter {
                    let new_counter = Counter {
                        calls: 0,
                        duration: Duration::from_secs(0),
                    };
                    calls.insert(name.clone(), new_counter);
                    counter = calls.get_mut(&name);
                }
                counter.map(|counter| {
                    counter.calls += 1;
                    counter.duration += duration;
                });
            }
        }
        let mut calls: Vec<(String, Counter)> = calls.into_iter().collect();
        calls.sort_unstable_by(|l, r| r.1.duration.cmp(&l.1.duration));
        let total_time = total_time.as_micros() as f64 / 1_000_000.0;
        let total_calls = calls.iter().fold(0, |i, (_, c)| i + c.calls);
        // TODO: dynamic columns
        println!(" % time     seconds  usecs/call     calls    errors syscall");
        println!("------ ------------ ----------- --------- --------- ----------------");
        for row in calls.into_iter() {
            let row_time = row.1.duration.as_micros() as f64 / 1_000_000.0;
            let per_call = row_time / row.1.calls as f64;
            let percent: f64 = row_time / total_time * 100.0;
            println!(
                "{:6.2} {:12.6} {:11.6} {:9} {:9} {}",
                percent, row_time, per_call, row.1.calls, " ", row.0
            );
        }
        println!("------ ------------ ----------- --------- --------- ----------------");
        println!(
            "100.00 {:12.6}             {:9}           total",
            total_time, total_calls
        );
        // % time     seconds  usecs/call     calls    errors syscall
        // ------ ----------- ----------- --------- --------- ----------------
        //   0.00    0.000000           0         8           read
        // ...
        //   0.00    0.000000           0         1           getrandom
        // ------ ----------- ----------- --------- --------- ----------------
        // 100.00    0.000000                    99         9 total
    }
    Ok(())
}
