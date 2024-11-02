pub trait FromBytes {
    fn read_le_bytes(input: &mut &[u8]) -> Self;
}

macro_rules! impl_from_bytes {
    ($t:ty $(,$ts:ty)* $(,)?) => {
        impl FromBytes for $t {
            fn read_le_bytes(input: &mut &[u8]) -> Self {
            let (bytes, rest) = input.split_at(std::mem::size_of::<Self>());
            *input = rest;
            Self::from_le_bytes(bytes.try_into().unwrap())
            }
        }

        impl_from_bytes!($($ts,)*);
    };
    ($(,)?) => {};
}

impl_from_bytes!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
