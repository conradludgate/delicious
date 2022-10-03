use criterion::{black_box, criterion_group, criterion_main, Criterion};
use no_way::{
    jwa::{cea, kma, sign},
    jwe, jwk,
    jws::Unverified,
    ClaimsSet,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Serialize, Deserialize)]
pub struct Payload {
    payload: String,
}

fn claims() -> ClaimsSet<Payload> {
    ClaimsSet {
        registered: no_way::RegisteredClaims {
            issuer: Some("delicious-analytics".into()),
            issued_at: Some(OffsetDateTime::now_utc().into()),
            ..Default::default()
        },
        private: Payload {
            payload: PAYLOAD.to_owned(),
        },
    }
}

fn sign(jwt: no_way::JWT<Payload>) -> Unverified<ClaimsSet<Payload>> {
    let key = jwk::OctetKey::new((0..32).collect());
    jwt.encode::<sign::HS256>(&key).unwrap()
}

fn parse_jwt(jwt: &str) -> Unverified<ClaimsSet<Payload>> {
    jwt.parse().unwrap()
}

fn verify(jwt: Unverified<ClaimsSet<Payload>>) -> no_way::JWT<Payload> {
    let key = jwk::OctetKey::new((0..32).collect());
    jwt.verify::<sign::HS256>(&key).unwrap()
}

fn signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");

    let jwt = no_way::JWT::new(claims());

    group.bench_function("sign", |b| b.iter(|| sign(black_box(jwt.clone()))));

    let signed = sign(jwt);

    group.bench_function("format", |b| b.iter(|| black_box(&signed).to_string()));

    let token = signed.to_string();

    group.bench_function("parse", |b| b.iter(|| parse_jwt(black_box(&token))));

    group.bench_function("verify", |b| b.iter(|| verify(black_box(signed.clone()))));
}

fn encrypt(jwe: jwe::Decrypted<ClaimsSet<Payload>>) -> jwe::Encrypted<kma::PBES2_HS512_A256KW> {
    let key = jwk::OctetKey::new((0..32).collect());
    let header = kma::Pbes2Header {
        count: 500,
        salt: vec![0; 16],
    };
    jwe.encrypt::<cea::A256GCM, kma::PBES2_HS512_A256KW>(&key, header)
        .unwrap()
}

fn parse_jwe(jwe: &str) -> jwe::Encrypted<kma::PBES2_HS512_A256KW> {
    jwe.parse().unwrap()
}

fn decrypt(jwe: jwe::Encrypted<kma::PBES2_HS512_A256KW>) -> jwe::Decrypted<ClaimsSet<Payload>> {
    let key = jwk::OctetKey::new((0..32).collect());
    jwe.decrypt::<_, cea::A256GCM>(&key).unwrap()
}

fn encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");

    let jwe = jwe::Decrypted::new(claims());

    group.bench_function("encrypt", |b| b.iter(|| encrypt(black_box(jwe.clone()))));

    let signed = encrypt(jwe);

    group.bench_function("format", |b| b.iter(|| black_box(&signed).to_string()));

    let token = signed.to_string();

    group.bench_function("parse", |b| b.iter(|| parse_jwe(black_box(&token))));

    group.bench_function("decrypt", |b| b.iter(|| decrypt(black_box(signed.clone()))));
}

criterion_group!(benches, signing, encryption);
criterion_main!(benches);

static PAYLOAD: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Interdum velit euismod in pellentesque massa placerat duis ultricies. Gravida neque convallis a cras semper auctor neque. Eget duis at tellus at urna condimentum mattis pellentesque. Commodo ullamcorper a lacus vestibulum sed arcu non odio. Amet consectetur adipiscing elit pellentesque habitant. Ipsum a arcu cursus vitae congue mauris. Egestas fringilla phasellus faucibus scelerisque. Ipsum suspendisse ultrices gravida dictum fusce ut placerat orci nulla. Tristique senectus et netus et malesuada. A diam maecenas sed enim ut sem viverra aliquet eget. Blandit aliquam etiam erat velit scelerisque in dictum non. Venenatis cras sed felis eget velit aliquet sagittis. Lectus mauris ultrices eros in cursus turpis massa tincidunt dui.
Etiam non quam lacus suspendisse faucibus. Feugiat nisl pretium fusce id velit ut. Ut eu sem integer vitae justo eget magna. Leo duis ut diam quam nulla porttitor massa. Vestibulum lorem sed risus ultricies tristique nulla. Vulputate enim nulla aliquet porttitor lacus luctus accumsan tortor. Aenean euismod elementum nisi quis eleifend quam. Sed augue lacus viverra vitae congue eu consequat. Sed adipiscing diam donec adipiscing. Sed nisi lacus sed viverra tellus. Gravida neque convallis a cras semper auctor neque vitae. At lectus urna duis convallis convallis tellus. Leo a diam sollicitudin tempor id eu. Donec ultrices tincidunt arcu non sodales. Purus sit amet luctus venenatis lectus magna fringilla urna.
Id leo in vitae turpis massa. Penatibus et magnis dis parturient montes nascetur ridiculus. Curabitur vitae nunc sed velit dignissim sodales. Tincidunt arcu non sodales neque. Mi tempus imperdiet nulla malesuada pellentesque. Neque convallis a cras semper auctor neque. Sagittis purus sit amet volutpat consequat mauris. Varius quam quisque id diam. Auctor eu augue ut lectus arcu. Mauris nunc congue nisi vitae suscipit. Felis eget nunc lobortis mattis aliquam faucibus purus. Amet massa vitae tortor condimentum lacinia quis vel eros donec. Tincidunt arcu non sodales neque sodales ut etiam. Est placerat in egestas erat.
Cras adipiscing enim eu turpis egestas. Amet tellus cras adipiscing enim eu. Viverra mauris in aliquam sem fringilla ut morbi tincidunt. Est pellentesque elit ullamcorper dignissim cras tincidunt lobortis feugiat. Scelerisque purus semper eget duis at tellus. Est ullamcorper eget nulla facilisi etiam dignissim diam quis. Risus sed vulputate odio ut. Eget aliquet nibh praesent tristique magna sit. Vestibulum lectus mauris ultrices eros in. Velit egestas dui id ornare arcu. Ac tortor vitae purus faucibus ornare suspendisse. Faucibus in ornare quam viverra. Nisl rhoncus mattis rhoncus urna neque viverra justo nec ultrices. In massa tempor nec feugiat nisl. Mauris pellentesque pulvinar pellentesque habitant. Duis convallis convallis tellus id.
Aliquet risus feugiat in ante metus dictum at tempor. Id velit ut tortor pretium viverra. Fringilla ut morbi tincidunt augue. Sed id semper risus in. Diam maecenas ultricies mi eget mauris pharetra et ultrices neque. Et magnis dis parturient montes nascetur ridiculus mus. Vitae sapien pellentesque habitant morbi tristique senectus et. Dui vivamus arcu felis bibendum ut. Velit ut tortor pretium viverra suspendisse potenti nullam ac. Augue neque gravida in fermentum et.";
