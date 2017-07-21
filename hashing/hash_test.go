package hashing

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const (
	original              = "HelloWorld1"
	saltedAndPepperedSalt = "56c01edd9608037d4d262ebb6186b5e092c780a7edca161b43818f346d45c7ad"
	saltedAndPepperedHash = "fe2bb81c63ef3187dd5ef0d92f474d4483f2c11ca8c4c4c5fc3a9e1c56b32b5e946ad6bb95b50381a87b7ea295b48ff9999ff71023399d90463d5d011ea6fd57"
	saltedHash            = "6e580ce55ddbb1e7d6d616b6c8480a4b90875c459ce7a0b59f30ace96995e3b11173c0456754b73827fbd27e9d15c52772e2f409b87003321bce6be97852c2ec"
	saltedSalt            = "2cc9ae49bd3fd3d223b5de3b40efb0c0ebcd3387117f0d8a3b680f286ece94a9"
	plainHash             = "a4db351d57adf4b71105ef2b13138ea50d539c93a83b471974a7a7c1f8b132cd267e11266529eaaf08f05e516dbebf03133688826cb538eebc626bb06ad1ebd8"
	bcryptHash            = "24326124313024377a535a4f5a38777253785462497a2e734e51674b2e43586e7439416249314c7770356572374542484836586f586e7978754f69322432612431302477717359596a676d485346542f4532675153747649756c575377715a554e65425a55416a4268656b546453597542554675546f7347243261243130245837712e495345656d694f54586e586162415153724f4975467352376b63377a62726c6654746a46687962565459552e2f73487443243261243130244d33674c7a70377a6d6a2f3073706f3032554c7646654b4a4564424c5556654a65444b47376577516f677647726478693132576a36243261243130246f554f41694e674b317464763479394e325a46504165625a50734b6e39765679532f7a6f5a31666647637a50542f685135766659432432612431302431516a61484938766651514d516a45354738415a682e366d376c316730737362464d536f76554e7038585477414668486d31417036243261243130242f65525457656b42424c5a30674e5a42614a49745a4f3246664430767943336d6a52476d7155663473794d423147672e6e544c414b2000000000"
)

var peppers = []string{
	"47278c6cd6353a278a2a5929f77752ac429acd59cbded92cdf88a68fdfb9ac2f",
	"b0aa0db641509c907459bf95445a78413dc310b2fdd2d8962562d8e3327a04e0",
	"90ffbdb56950f4be181f752d8fe2f9dad682ef22fc163429ebe288bbc0a91804",
	"189f58d27aa9e979e685acdb10e8587a09e1bcae4ec93bea05522f4e5b32f3b5",
	"e1e9c4e5bcafc552ded0c849fbc896bd6fa7c03c0410b60d1e7541832be66fa6",
}

func BenchmarkGeneratePlainHash(b *testing.B) {
	h := New(peppers)

	for i := 0; i < b.N; i++ {
		_, _ = h.GenerateHash(original, false, false)
	}
}

func BenchmarkGenerateHashWithSaltAndPepper(b *testing.B) {
	h := New(peppers)

	for i := 0; i < b.N; i++ {
		_, _ = h.GenerateHash(original, true, true)
	}
}

func BenchmarkGenerateBcrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bcrypt.GenerateFromPassword([]byte(original), bcrypt.DefaultCost)
	}
}

func BenchmarkCompareHash5Peppers(b *testing.B) { benchmarkCompare(5, b) }

func BenchmarkCompareHash10Peppers(b *testing.B) { benchmarkCompare(10, b) }

func BenchmarkCompareHash100Peppers(b *testing.B) { benchmarkCompare(100, b) }

func BenchmarkCompareHash1000Peppers(b *testing.B) { benchmarkCompare(1000, b) }

func benchmarkCompare(pepperSize int, b *testing.B) {
	p := generatePeppers(pepperSize)
	h := New(p)
	hash, salt := h.GenerateHash(original, true, true)

	for i := 0; i < b.N; i++ {
		h.Compare(original, salt, true, hash)
	}
}

func BenchmarkCompareSaltedHash(b *testing.B) {
	h := New(peppers)
	hash, salt := h.GenerateHash(original, true, false)

	for i := 0; i < b.N; i++ {
		h.Compare(original, salt, false, hash)
	}
}

func BenchmarkComparePlainHash(b *testing.B) {
	h := New(peppers)
	hash, _ := h.GenerateHash(original, false, false)

	for i := 0; i < b.N; i++ {
		h.Compare(original, "", false, hash)
	}
}

func BenchmarkCompareBCrypt(b *testing.B) {
	hash, _ := bcrypt.GenerateFromPassword([]byte(original), bcrypt.DefaultCost)

	for i := 0; i < b.N; i++ {
		bcrypt.CompareHashAndPassword(hash, []byte(original))
	}
}

func TestGenerateHash(t *testing.T) {
	h := New(peppers)
	hash, salt := h.GenerateHash(original, true, true)

	fmt.Println("Salted and Peppered Hash")
	fmt.Println("Salt: ", salt)
	fmt.Println("Hash: ", hash)
	fmt.Println("-----")
}

func TestGenerateSaltedHash(t *testing.T) {
	h := New(peppers)
	hash, salt := h.GenerateHash(original, true, false)

	fmt.Println("Salted Hash")
	fmt.Println("Hash: ", hash)
	fmt.Println("Salt: ", salt)
	fmt.Println("-----")
}

func TestGeneratePlainHash(t *testing.T) {
	h := New(peppers)
	hash, _ := h.GenerateHash(original, false, false)

	fmt.Println("Plain Hash")
	fmt.Println("Hash: ", hash)
	fmt.Println("-----")
}

func TestCompareSaltedAndPeppered(t *testing.T) {
	h := New(peppers)
	success := h.Compare(original, saltedAndPepperedSalt, true, saltedAndPepperedHash)

	if !success {
		t.Fatal("Should have successfully compared to original")
	}
}

func TestComparesSaltedCorrectly(t *testing.T) {
	h := New(peppers)
	success := h.Compare(original, saltedSalt, false, saltedHash)

	if !success {
		t.Fatal("Should have successfully compared to original")
	}
}

func TestComparesPlainCorrectly(t *testing.T) {
	h := New(peppers)
	success := h.Compare(original, "", false, plainHash)

	if !success {
		t.Fatal("Should have successfully compared to original")
	}
}

func TestSomething(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	hash2, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

	if bytes.Compare(hash, hash2) != 0 {
		fmt.Printf("%x\n", hash)
		fmt.Printf("%x\n", hash2)
		t.Fail()
	}
}

func generatePeppers(n int) []string {
	p := make([]string, 0)

	for i := 0; i < n; i++ {
		h := GenerateRandomSalt()
		p = append(p, h)
	}

	return p
}
