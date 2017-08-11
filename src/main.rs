extern crate curl;
extern crate futures;
extern crate futures_cpupool;
extern crate jobserver;
extern crate rustc_demangle;
extern crate serde_json;
extern crate tempdir;
extern crate tokio_core;
extern crate tokio_curl;
extern crate tokio_process;

#[macro_use]
extern crate serde_derive;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::vec;

use curl::easy::Easy;
use futures::future::ok;
use futures::sync::mpsc;
use futures::{Future, Async, Poll, Stream};
use futures_cpupool::CpuPool;
use tempdir::TempDir;
use tokio_core::reactor::{Core, Handle};
use tokio_curl::Session;
use tokio_process::CommandExt;

#[derive(Serialize, Deserialize)]
struct Analysis {
    krate: Crate,
    upstream_deps: usize,
    dependencies_size: usize,
    local_size: usize,
}

fn main() {
    let arg = env::args().nth(1);
    match arg.as_ref().map(|s| &**s) {
        Some("out.json") => {
            let mut contents = String::new();
            File::open("out.json").unwrap().read_to_string(&mut contents).unwrap();
            let analyses: Vec<Option<Analysis>> = serde_json::from_str(&contents).unwrap();
            for analysis in analyses.into_iter().filter_map(|x| x) {
                if analysis.local_size > 0 {
                    println!("{},{},{},{},{}",
                             analysis.upstream_deps,
                             analysis.dependencies_size as f64 / (analysis.local_size as f64),
                             analysis.krate.name,
                             analysis.dependencies_size,
                             analysis.local_size);
                }
            }
            return
        }
        Some(p) => {
            let file = env::args().nth(2).unwrap();
            let (deps, local) = analyze_file(Path::new(&file), p).unwrap();
            println!("deps={} local={}", deps, local);
            return
        }
        None => {}
    }
    let srv = jobserver::Client::new(16).unwrap();
    let (tx, token_rx) = mpsc::unbounded();
    let helper = srv.clone().into_helper_thread(move |token| {
        (&tx).send(token).unwrap();
    }).unwrap();

    let pool = CpuPool::new_num_cpus();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let session = Session::new(handle.clone());
    let builds = AllCrates::new(session).take(1000);
    let builds = builds.map(|build| {
        helper.request_token();
        build
    });
    let builds = builds.zip(token_rx.map_err(|()| panic!()));

    let crates = builds.map(|(krate, token)| {
        analyze(krate, &handle, &pool, srv.clone()).map(|result| {
            drop(token);
            result
        })
    }).buffer_unordered(100);

    let crates = core.run(crates.collect()).unwrap();

    let json = serde_json::to_string(&crates).unwrap();
    File::create("out.json")
        .unwrap()
        .write_all(json.as_bytes())
        .unwrap();
    println!("{}", json);
}

fn analyze(krate: Crate,
           handle: &Handle,
           pool: &CpuPool,
           client: jobserver::Client) -> MyFuture<Option<Analysis>> {
    let cwd = pool.spawn_fn(|| -> io::Result<_> {
        let dir = TempDir::new("analyze")?;
        println!("analyzing: {}", krate.name);
        File::create(dir.path().join("Cargo.toml"))?.write_all(format!("
            [package]
            name = 'foo'
            version = '0.1.0'
            authors = []

            [dependencies]
            {} = '={}'

            [lib]
            path = 'lib.rs'
        ", krate.name, krate.max_version).as_bytes())?;

        File::create(dir.path().join("lib.rs"))?;

        Ok((dir, krate))
    });

    let handle = handle.clone();
    let cwd = cwd.and_then(move |(dir, krate)| {
        let mut cmd = Command::new("cargo");
        client.configure(&mut cmd);
        cmd
            .arg("+nightly")
            .arg("rustc")
            .arg("--lib")
            .arg("-p").arg(&krate.name)
            .arg("--manifest-path").arg(dir.path().join("Cargo.toml"))
            .arg("--")
            .arg("--emit").arg("llvm-ir");
        cmd.output_async(&handle).map(|a| (a, dir, krate))
    });

    let pool = pool.clone();
    Box::new(cwd.and_then(move |(output, dir, krate)| -> MyFuture<_> {
        if !output.status.success() {
            println!("failed to compile: {}", krate.name);
            Box::new(ok(None))
        } else {
            Box::new(pool.spawn_fn(move || {
                find_and_analyze(dir.path(), krate).map(Some)
            }))
        }
    }))
}

fn find_and_analyze(path: &Path, krate: Crate) -> io::Result<Analysis> {
    let lock = path.join("Cargo.lock");
    let mut contents = String::new();
    File::open(&lock)?.read_to_string(&mut contents)?;
    let upstream_deps = contents
        .lines()
        .filter(|s| s.starts_with("[[package]]"))
        .count();

    let target = path.join("target/debug/deps");
    for file in target.read_dir()? {
        let file = file?;
        let path = file.path();
        if path.extension().and_then(|s| s.to_str()) == Some("ll") {
            let to_find = format!("{}-{}", krate.name, krate.max_version);
            let (dependencies, local) = analyze_file(&path, &to_find)?;
            return Ok(Analysis {
                krate: krate,
                dependencies_size: dependencies,
                local_size: local,
                upstream_deps: upstream_deps,
            })
        }
    }
    panic!("no IR found")
}

fn analyze_file(ir: &Path, to_find: &str) -> io::Result<(usize, usize)> {
    let mut contents = String::new();

    File::open(ir)?.read_to_string(&mut contents)?;

    let mut state = State::None;

    let mut syms = Vec::new();
    let mut dbg = Vec::new();

    enum State<'a> {
        None,
        Define { name: &'a str, lines: usize, dbg: usize },
    }

    for line in contents.lines() {
        match state {
            State::None => {
                if line.starts_with("define") {
                    let at_sign = line.find('@').expect("at-sign");
                    let line = &line[at_sign + 1..];
                    let open_paren = line.find('(').expect("left paren");
                    let symbol = line[..open_paren].trim_matches('"');
                    if symbol == "main" {
                        continue
                    }
                    let dbg = line.find("!dbg").expect("dbg");
                    let dbg = line[dbg..]
                        .split_whitespace()
                        .nth(1)
                        .expect("no number after debug")
                        .trim_left_matches('!')
                        .parse::<usize>()
                        .expect("failed to parse as number");

                    state = State::Define { name: symbol, dbg: dbg, lines: 0 };
                } else if line.starts_with("!") {
                    let line = &line[1..];
                    let space = line.find(" ").unwrap();
                    let num = &line[..space];
                    if num.starts_with("llvm") {
                        continue
                    }
                    let num = num.parse::<usize>().expect("dbg failed parsed");
                    assert_eq!(dbg.len(), num);
                    dbg.push(&line[space + 3..]);
                }
            }
            State::Define { name, lines, dbg } => {
                if line.starts_with("}") {
                    syms.push((name, lines, dbg));
                    state = State::None;
                } else {
                    state = State::Define {
                        name: name,
                        lines: lines + 1,
                        dbg: dbg,
                    };
                }
            }
        }
    }

    let mut dependencies = 0;
    let mut local = 0;
    for (_name, lines, dbg_idx) in syms {
        let dbg_line = dbg[dbg_idx];
        assert!(dbg_line.contains("DISubprogram"));
        let file = dbg_line.find("file: ").expect("no file listed");
        let file = dbg_line[file..]
            .split_whitespace()
            .nth(1)
            .expect("not listed after file")
            .trim_left_matches('!')
            .trim_right_matches(',')
            .parse::<usize>()
            .expect("failed to parse file");
        let file = dbg[file];
        let filename = file[file.find("filename:").unwrap()..]
            .split_whitespace()
            .nth(1)
            .expect("not listed after filename")
            .trim_left_matches('"')
            .trim_right_matches(',')
            .trim_right_matches('"');
        let directory = file[file.find("directory:").unwrap()..]
            .split_whitespace()
            .nth(1)
            .expect("not listed after directory")
            .trim_left_matches('"')
            .trim_right_matches(',')
            .trim_right_matches(')')
            .trim_right_matches('"');

        let path = format!("{}/{}", directory, filename);
        if path.contains(&to_find) {
            local += lines;
        } else {
            dependencies += lines;
        }
    }

    Ok((dependencies, local))
}

type MyFuture<T> = Box<Future<Item = T, Error = io::Error>>;

struct AllCrates {
    session: Session,
    pending: vec::IntoIter<Crate>,
    page: usize,
    fetching: Option<MyFuture<Crates>>,
}

#[derive(Deserialize)]
struct Crates {
    crates: Vec<Crate>,
}

#[derive(Deserialize, Serialize)]
struct Crate {
    name: String,
    max_version: String,
}

impl AllCrates {
    pub fn new(session: Session) -> AllCrates {
        AllCrates {
            session: session,
            pending: Vec::new().into_iter(),
            page: 1,
            fetching: None,
        }
    }

    fn update_with(&mut self, crates: Crates) -> bool {
        if crates.crates.len() == 0 {
            return false
        }
        self.pending = crates.crates.into_iter();
        return true
    }
}

impl Stream for AllCrates {
    type Item = Crate;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, io::Error> {
        loop {
            if let Some(item) = self.pending.next() {
                return Ok(Some(item).into())
            }

            match self.fetching.poll()? {
                Async::Ready(None) => {}
                Async::Ready(Some(builds)) => {
                    self.fetching = None;
                    if !self.update_with(builds) {
                        return Ok(None.into())
                    }
                    continue
                }
                Async::NotReady => return Ok(Async::NotReady),
            }

            let url = format!("https://crates.io/api/v1/crates?page={}", self.page);
            self.page += 1;
            self.fetching = Some(Box::new(fetch(&self.session, &url).and_then(|data| {
                serde_json::from_slice(&data).map_err(err)
            })));
        }
    }
}

fn fetch(session: &Session, url: &str) -> MyFuture<Vec<u8>> {
    let mut data = Arc::new(Mutex::new(Vec::new()));
    let mut req = Easy::new();
    let data2 = data.clone();
    req.get(true).unwrap();
    req.url(url).unwrap();
    req.write_function(move |buf| {
        data2.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }).unwrap();

    Box::new(session.perform(req).map(move |req| {
        drop(req);
        mem::replace(Arc::get_mut(&mut data)
                        .expect("not unique arc?")
                        .get_mut()
                        .unwrap(),
                     Vec::new())
    }).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e.to_string())
    }))

}

fn err<E: std::error::Error + 'static + Send + Sync>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}
