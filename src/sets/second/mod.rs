mod eleven;
mod nine;
mod ten;
mod thirteen;
mod twelve;

#[cfg(test)]
mod tests {
    use super::{eleven, nine, ten, thirteen, twelve};

    #[test]
    fn nine() {
        assert_eq!(
            nine::run("YELLOW SUBMARINE", 20).unwrap(),
            "YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }

    #[test]
    fn ten() {
        assert_eq!(
            ten::run(
                "data/second/2.txt",
                "YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            .unwrap(),
            "CRIwqt4+szDbqkNY+I0qbNXPg1XLaCM5etQ5Bt9DRFV/xIN2k8Go7jtArLIyP605b071DL8C+FPYSHOXPkMMMFPAKm+Nsu0nCBMQVt9mlluHbVE/yl6VaBCjNuOGvHZ9WYvt51uR/lklZZ0ObqD5UaC1rupZwCEK4pIWf6JQ4pTyPjyiPtKXg54FNQvbVIHeotUG2kHEvHGS/w2Tt4E42xEwVfi29J3yp0O/TcL7aoRZIcJjMV4qxY/uvZLGsjo1/IyhtQp3vY0nSzJjGgaLYXpvRn8TaAcEtH3cqZenBooxBH3MxNjD/TVf3NastEWGnqeGp+0D9bQx/3L0+xTf+k2VjBDrV9HPXNELRgPN0MlNo79p2gEwWjfTbx2KbF6htgsbGgCMZ6/iCshy3R8/abxkl8eK/VfCGfA6bQQkqs91bgsT0RgxXSWzjjvh4eXTSl8xYoMDCGa2opN/b6Q2MdfvW7rEvp5mwJOfQFDtkv4M5cFEO3sjmU9MReRnCpvalG3ark0XC589rm+42jC4/oFWUdwvkzGkSeoabAJdEJCifhvtGosYgvQDARUoNTQAO1+CbnwdKnA/WbQ59S9MU61QKcYSuk+jK5nAMDot2dPmvxZIeqbB6ax1IH0cdVx7qB/Z2FlJ/U927xGmC/RUFwoXQDRqL05L22wEiF85HKx2XRVB0F7keglwX/kl4gga5rk3YrZ7VbInPpxUzgEaE4+BDoEqbv/rYMuaeOuBIkVchmzXwlpPORwbN0/RUL89xwOJKCQQZM8B1YsYOqeL3HGxKfpFo7kmArXSRKRHToXuBgDq07KS/jxaS1a1Paz/tvYHjLxwY0Ot3kS+cnBeq/FGSNL/fFV3J2a8eVvydsKat3XZS3WKcNNjY2ZEY1rHgcGL5bhVHs67bxb/IGQleyY+EwLuv5eUwS3wljJkGcWeFhlqxNXQ6NDTzRNlBS0W4CkNiDBMegCcOlPKC2ZLGw2ejgr2utoNfmRtehr+3LAhLMVjLyPSRQ/zDhHjXu+Kmt4elmTmqLgAUskiOiLYpr0zI7Pb4xsEkcxRFX9rKy5WV7NhJ1lR7BKyalO94jWIL4kJmh4GoUEhO+vDCNtW49PEgQkundV8vmzxKarUHZ0xr4feL1ZJTHinyUs/KUAJAZSAQ1Zx/S4dNj1HuchZzDDm/nE/Y3DeDhhNUwpggmesLDxFtqJJ/BRn8cgwM6/SMFDWUnhkX/t8qJrHphcxBjAmIdIWxDi2d78LA6xhEPUwNdPPhUrJcu5hvhDVXcceZLa+rJEmn4aftHm6/Q06WH7dq4RaaJePP6WHvQDpzZJOIMSEisApfh3QvHqdbiybZdyErz+yXjPXlKWG90kOz6fx+GbvGcHqibb/HUfcDosYA7lY4xY17llY5sibvWM91ohFN5jyDlHtngi7nWQgFcDNfSh77TDTzltUp9NnSJSgNOOwoSSNWadm6+AgbXfQNX6oJFaU4LQiAsRNa7vX/9jRfi655uvujM4ob199CZVxEls10UI9pIemAQQ8z/3rgQ3eyL+fViyztUPg/2IvxOHveexE4owH4Fo/bRlhZK0mYIamVxsRADBuBlGqx1b0OuF4AoZZgUM4d8v3iyUufeh0QQqOkvJK/svkYHn3mf4JlUb2MTgtRQNYdZKDRgF3Q0IJaZuMyPWFsSNTYauWjMVqnj0AEDHh6QUMF8bXLM0jGwANP+r4yPdKJNsoZMpuVoUBJYWnDTV+8Ive6ZgBi4EEbPbMLXuqDMpDi4XcLE0UUPJ8VnmO5fAHMQkA64esY2QqldZ+5gEhjigueZjEf0917/X53ZYWJIRiICnmYPoM0GSYJRE0k3ycdlzZzljIGk+PQ7WgeJhthisEBDbgTuppqKNXLbNZZG/VaTdbpW1ylBv0eqamFOmyrTyh1APSGn37comTI3fmN6/wmVnmV4/FblvVwLuDvGgSCGPOF8i6FVfKvdESs+yr+1AEDJXfp6h0eNEUsM3gXaJCknGhnt3awtg1fSUiwpYfDKZxwpPOYUuer8Wi+VCDsWsUpkMxhhRqOBKaQaBDQG+kVJu6aPFlnSPQQTi1hxLwi0l0Rr38xkr+lHU7ix8LeJVgNsQdtxbovE3i7z3ZcTFY7uJkI9j9E0muDN9x8y/YN25rm6zULYaOjUoP/7FQZsSgxPIUvUiXkEq+FU2h0FqAC7H18cr3Za5x5dpw5nwawMArKoqG9qlhqc34lXV0ZYwULu58EImFIS8+kITFuu7jOeSXbBgbhx8zGPqavRXeiu0tbJd0gWs+YgMLzXtQIbQuVZENMxJSZB4aw5lPA4vr1fFBsiU4unjOEo/XAgwrTc0w0UndJFPvXRr3Ir5rFoIEOdRo+6os5DSlk82SBnUjwbje7BWsxWMkVhYO6bOGUm4VxcKWXu2jU66TxQVIHy7WHktMjioVlWJdZC5Hq0g1LHg1nWSmjPY2c/odZqN+dBBC51dCt4oi5UKmKtU5gjZsRSTcTlfhGUd6DY4Tp3CZhHjQRH4lZhg0bF/ooPTxIjLKK4r0+yR0lyRjqIYEY27HJMhZDXFDxBQQ1UkUIhAvXacDWB2pb3YyeSQjt8j/WSbQY6TzdLq8SreZiuMWcXmQk4EH3xu8bPsHlcvRI+B3gxKeLnwrVJqVLkf3m2cSGnWQhSLGbnAtgQPA6z7u3gGbBmRtP0KnAHWSK7q6onMoYTH+b5iFjCiVRqzUBVzRRKjAL4rcL2nYeV6Ec3PlnboRzJwZIjD6i7WCdcxERr4WVOjOBX4fhhKUiVvlmlcu8CkIiSnZENHZCpI41ypoVqVarHpqh2aP/PS624yfxx2N3C2ci7VIuH3DcSYcaTXEKhz/PRLJXkRgVlWxn7QuaJJzDvpBoFndoRu1+XCsup/AtkLidsSXMFTo/2Ka739+BgYDuRt1mE9EyuYyCMoxO/27sn1QWMMd1jtcv8Ze42MaM4y/PhAMp2RfCoVZALUS2K7XrOLl3s9LDFOdSrfD8GeMciBbfLGoXDvv5Oqq0S/OvjdID94UMcadpnSNsist/kcJJV0wtRGfALG2+UKYzEj/2TOiN75UlRvA5XgwfqajOvmIIXybbdhxpjnSB04X3iY82TNSYTmLLAzZlX2vmV9IKRRimZ2SpzNpvLKeB8lDhIyGzGXdiynQjFMNcVjZlmWHsH7eItAKWmCwNkeuAfFwir4TTGrgG1pMje7XA7kMT821cYbLSiPAwtlC0wm77F0Ta7jdMrLjMO29+1958CEzWPdzdfqKzlfBzsba0+dS6mcW/YTHaB4bDyXechZBk/35fUg+4geMj6PBTqLNNWXBX93dFC7fNyda+Lt9cVJnlhIi/61fr0KzxOeXNKgePKOC3Rz+fWw7Bm58FlYTgRgN63yFWSKl4sMfzihaQq0R8NMQIOjzuMl3Ie5ozSa+y9g4z52RRc69l4n4qzf0aErV/BEe7FrzRyWh4PkDj5wy5ECaRbfO7rbs1EHlshFvXfGlLdEfP2kKpT9U32NKZ4h+Gr9ymqZ6isb1KfNov1rw0KSqYNP+EyWCyLRJ3EcOYdvVwVb+vIiyzxnRdugB3vNzaNljHG5ypEJQaTLphIQnlP02xcBpMNJN69bijVtnASN/TLV5ocYvtnWPTBKu3OyOkcflMaHCEUgHPW0fmGfld4i9Tu35zrKvTDzfxkJX7+KJ72d/V+ksNKWvwn/wvMOZsa2EEOfdCidmoql027IS5XvSHynQtvFmw0HTk9UXt8HdVNTqcdy/jUFmXpXNP2Wvn8PrU2DhkkIzWhQ5Rxd/vnM2QQr9Cxa2J9GXEV3kGDiZV90+PCDSVGY4VgF8y7GedI1h"        
        );
    }

    #[test]
    fn eleven() {
        use rand::Rng;
        let cbc_or_not = rand::thread_rng().gen::<bool>();
        let pt = "0123456789abcdef0123456789abcdef0123456789abcdef".as_bytes();
        assert_eq!(eleven::run(&base64::encode(&pt), cbc_or_not), cbc_or_not);
    }

    #[test]
    fn twelve() {
        use rand::Rng;
        let key = rand::thread_rng().gen::<[u8; 16]>();
        assert_eq!(
            twelve::run(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
                &base64::encode(&key)
            ).unwrap(),
            (16, true, "Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
".to_string())
        );
    }

    #[test]
    fn thirteen() {
        assert_eq!(
            thirteen::run("foos@ball.com&role=admin").unwrap(),
            ((
                "{
\temail: 'foos@ball.comroleadmin',
\tuid: '10',
\trole: 'user'
}"
                .to_string(),
                "{
\temail: 'foos@ball.com',
\tuid: '10',
\trole: 'admin'
}"
                .to_string()
            ))
        );
    }

}
