use http::parse;

pub fn main(item: pub [Field; 1], data: [Field; 1024]) -> pub Field {
    parse(data);
    item[0]
}

