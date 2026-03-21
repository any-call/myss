package myss

// SS2022 多用户 API
//
// 外部项目只需 import "github.com/any-call/myss"，
// 无需直接依赖 ss2022 子包。

import "github.com/any-call/myss/ss2022"

// SS2022Store 是多用户 SS2022 服务端的核心类型。
// 类型别名，与 ss2022.UserStore 是同一类型，方法完全一致。
type SS2022Store = ss2022.UserStore

// NewSS2022Store 创建一个多用户 SS2022 Store。
// serverKey 是 GenerateSS2022Key 生成的 base64 字符串。
// key 长度决定加密算法：16 字节 → AES-128-GCM，32 字节 → AES-256-GCM。
func NewSS2022Store(serverKey string) (*SS2022Store, error) {
	return ss2022.NewUserStore(serverKey)
}

// GenerateSS2022Key 生成一个合法的 SS2022 PSK。
// keySize 传 16（AES-128）或 32（AES-256）。
// 返回 base64 编码字符串，可直接用于 NewSS2022Store 或 store.AddUser。
func GenerateSS2022Key(keySize int) (string, error) {
	return ss2022.GenerateKey(keySize)
}
