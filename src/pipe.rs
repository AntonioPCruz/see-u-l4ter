#[macro_export]
macro_rules! pipe_fun {
    (&, $ret:expr) => {
        &$ret;
    };
    ((as $typ:ty), $ret:expr) => {
        $ret as $typ;
    };
    ({$fun:expr}, $ret:expr) => {
        $fun($ret);
    };
    ([$fun:ident], $ret:expr) => {
        $ret.$fun();
    };
    (($fun:ident($($arg:expr),*)), $ret:expr) => {
        $fun($ret $(,$arg)*);
    };
    ($fun:ident, $ret:expr) => {
        $fun($ret);
    }
}

#[macro_export]
macro_rules! pipe {
    ( $expr:expr |> $($funs:tt)=>+ ) => {
        {
            let ret = $expr;
            $(
                let ret = pipe_fun!($funs, ret);
            )*
            ret
        }
    };
}

#[macro_export]
macro_rules! pipe_res {
    ( $expr:expr |> $($funs:tt)=>+ ) => {
        {
            let ret = Ok($expr);
            $(
                let ret = match ret {
                    Ok(x) => pipe_fun!($funs, x),
                    _ => ret
                };
            )*
            ret
        }
    };
}

#[macro_export]
macro_rules! pipe_opt {
    ( $expr:expr |> $($funs:tt)=>+ ) => {
        {
            let ret = None;
            $(
                let ret = match ret {
                    None => pipe_fun!($funs, $expr),
                    _ => ret
                };
            )*
            ret
        }
    };
}
