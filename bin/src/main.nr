use http::parse;

// pub fn main(data: str<1024>)  {
//     parse(data);
// }

pub fn main(x0: pub Field, w0: Field, w1: Field) {
    assert(x0 * w0 + w1 + 2 == 0);
}
