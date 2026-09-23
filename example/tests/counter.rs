mod counter {
    xbpf::include_bpf!("counter");

    unsafe impl xbpf::Pod for types::args {}
}

#[xbpf::test(counter, add)]
fn adds() {
    let args = add(types::args { a: 2, b: 3, sum: 0 }).expect("add");
    assert_eq!(args.sum, 5);
}

#[xbpf::test(counter, add)]
fn fails_on_negative_input() {
    let args = types::args {
        a: -1,
        b: 3,
        sum: 0,
    };
    assert!(add(args).is_err());
}
