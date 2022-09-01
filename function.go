package utils

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// GeneOrderNo23
// 生成23位的订单号
func GeneOrderNo23() (orderNo string) {
	current := time.Now()
	orderNo = time.Unix(current.Unix(), 0).Format("20060102150405")
	second := strconv.Itoa(int(current.UnixMicro()) % 1000000)
	for len(second) < 6 {
		second = "0" + second
	}

	var n int
	for {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		n = r.Intn(1000000)
		if n >= 100 {
			break
		}
	}
	str := strconv.Itoa(n)
	for i := len(str); len(str) < 6; i++ {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		n = r.Intn(10)
		str = fmt.Sprintf("%s%d", str, n)
	}

	orderNo = fmt.Sprintf("%s%s%d", orderNo, second, n)
	return
}

//GeneOrderNo
//生成长度26位订单号
func GeneOrderNo() (orderNo string) {
	current := time.Now()
	orderNo = time.Unix(current.Unix(), 0).Format("20060102150405")
	second := strconv.Itoa(int(current.UnixMicro()) % 1000000)
	for len(second) < 6 {
		second = "0" + second
	}
	str := fmt.Sprintf("%06v", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000))

	return fmt.Sprintf("%s%s%s", orderNo, second, str)
}

// GeneRandCode
// 生成随机数
// num 生成的位数
func GeneRandCode(num int) string {
	slice := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	str := ""
	for len(str) < num {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		n := r.Intn(62)
		str += string(slice[n : n+1])
	}
	return str
}

// GeneFilePath
// root 根目录
// id 文件ID
// ext 文件扩展名 .jpg
// key 加密串
// isRand 文件名是否用随机数，如果为 false 则每次生成的文件名都一样
func GeneFilePath(root string, id uint, ext string, secret string, isRand bool) string {
	root = strings.Trim(root, "/")
	str := fmt.Sprintf("%v", id)
	for len(str) < 11 {
		str = "0" + str
	}
	slice := []byte(str)
	path := root + "/" + string(slice[0:2]) + "/" + string(slice[2:4]) + "/" + string(slice[4:6]) + "/" + string(slice[6:8]) + "/"

	var sign string
	if !isRand {
		sign = fmt.Sprintf("%v%v", secret, id)
	} else {
		sign = fmt.Sprintf("%v%v%v", secret, time.Now().UnixNano(), id)
	}

	m := md5.New()
	_, err := io.WriteString(m, sign)
	if err != nil {
		//log.Fatal(err)
		return err.Error()
	}
	arr := m.Sum(nil) //已经输出，但是是编码
	// 将编码转换为字符串
	filename := fmt.Sprintf("%x", arr)
	//return path + string([]byte(newArr)[8:24]) + ext
	return path + filename + ext
}

// CreateDir
// 创建目录
func CreateDir(path string) error {
	pos := strings.Index(path, ".")
	if pos >= 0 {
		pos = strings.LastIndex(path, "/")
		substr := []byte(path)[0:pos]
		path = string(substr)
	}
	path = strings.TrimRight(path, "/")
	if err := os.MkdirAll(path, 0766); err != nil {
		return err
	}
	return nil
}

// GeneToken
// 生成长度为55个字符的Token
// flag 0-9A-Za-z的字符
// id 可以负数的 int64
// secret 加密串
func GeneToken(flag byte, id int64, secret *string) (token string, err error) {
	const chars string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if !(flag >= 48 && flag <= 57 || flag >= 65 && flag <= 90 || flag >= 97 && flag <= 122) {
		err = errors.New("flag invalid")
		return
	}

	var symbol string // 符号位，负数用数字表示；正数用字母表示
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	if id < 0 {
		symbol = fmt.Sprintf("%d", r.Intn(10))
	} else {
		ix := r.Intn(52)
		symbol = fmt.Sprintf("%c", chars[ix])
	}
	//symbol = "5"
	str := fmt.Sprintf("%v", id)
	str = strings.TrimLeft(str, "-")
	for len(str) < 21 {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		ix := r.Intn(52)
		str = fmt.Sprintf("%c%s", chars[ix], str)
	}
	str = fmt.Sprintf("%c%s%v", flag, symbol, str)

	code := str + *secret

	m := md5.New()
	_, err = io.WriteString(m, code)
	if err != nil {
		return
	}
	code = fmt.Sprintf("%x", m.Sum(nil))

	var chr string
	var j, k int64 = 0, 0

	for i := 1; i <= 55; i++ {
		switch i {
		case 2, 3, 4, 5, 8, 11, 13, 15, 17, 20, 23, 27, 29, 31, 34, 37, 39, 41, 43, 44, 46, 49, 53:
			chr = str[j : j+1]
			j++
		default:
			chr = code[k : k+1]
			k++
		}
		token += chr
	}
	//return fmt.Sprintf("%s;%s;%s", str, code, result)
	return
}

// AnalyzeToken
// 解析 token
func AnalyzeToken(tokenStr *string, secret *string) (id int64, flag byte, err error) {
	if len(*tokenStr) != 55 {
		fmt.Printf("%v;%#v", *tokenStr, tokenStr)
		err = errors.New("token invalid1")
		return
	}
	var code, ids string
	for i := 0; i <= 54; i++ {
		chr := fmt.Sprintf("%c", (*tokenStr)[i])
		switch i + 1 {
		case 2, 3, 4, 5, 8, 11, 13, 15, 17, 20, 23, 27, 29, 31, 34, 37, 39, 41, 43, 44, 46, 49, 53:
			ids += chr
		default:
			code += chr
		}
	}
	m := md5.New()
	_, err = io.WriteString(m, ids+*secret)
	if err != nil {
		return
	}
	tmp := fmt.Sprintf("%x", m.Sum(nil))
	if code != tmp {
		fmt.Printf("code=%v;tmp=%v;secret=%v", code, tmp, *secret)
		err = errors.New("token invalid2")
		return
	}

	flag = ids[1:2][0]
	symbol := []byte(ids[2:3])[0]

	code = ids[5:]
	ids = ""
	for i := 0; i < len(code); i++ {
		chr := code[i : i+1]
		switch chr {
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9":
			ids += chr
		default:
		}
	}
	if symbol >= 48 && symbol <= 57 {
		ids = "-" + ids
	}
	id, err = strconv.ParseInt(ids, 10, 64)
	return
}

// DownLoad
// base 保存的文件路径，不含扩展名
// url 图片网址
// cover 是否覆盖
func DownLoad(base string, url string, cover bool) error {
	name := path.Base(url)
	if !cover {
		if _, err := os.Stat(base + name); err == nil {
			return nil
		}
	}

	v, err := http.Get(url)
	if err != nil {
		return err
	}
	defer v.Body.Close()
	content, e := ioutil.ReadAll(v.Body)
	if e != nil {
		return e
	}
	err = ioutil.WriteFile(base, content, 0666)
	if err != nil {
		return err
	}
	return nil
}

//CreateMutiDir 调用os.MkdirAll递归创建文件夹
func CreateMutiDir(filePath string) error {
	if !IsExist(filePath) {
		err := os.MkdirAll(filePath, os.ModePerm)
		if err != nil {
			fmt.Println("创建文件夹失败,error info:", err)
			return err
		}
		return err
	}
	return nil
}

//IsExist 判断所给路径文件/文件夹是否存在(返回true是存在)
func IsExist(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func JSONMethod(content interface{}) map[string]interface{} {
	var name map[string]interface{}
	if marshalContent, err := json.Marshal(content); err != nil {
		fmt.Println(err)
	} else {
		d := json.NewDecoder(bytes.NewReader(marshalContent))
		d.UseNumber() // 设置将float64转为一个number
		if err := d.Decode(&name); err != nil {
			fmt.Println(err)
		} else {
			for k, v := range name {
				name[k] = v
			}
		}
	}
	return name
}

func BuildSignQueryStr(p map[string]interface{}) (returnStr string) {
	keys := make([]string, 0, len(p))
	for k := range p {
		if k == "sign" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	for _, k := range keys {
		if p[k] == "" {
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(fmt.Sprintf("%s", p[k]))
	}
	returnStr = buf.String()
	return
}

//From10to36
//10进制转36进制
func From10to36(n int64) (val string) {
	dict := "0RGJKD43SM8NL2AYBZQ7WX69ECH5U1VOIPFT"
	for n > 0 {
		ix := n % 36
		val = dict[ix:ix+1] + val
		n = n / 36
	}
	if val == "" {
		val = dict[0:1]
	}
	return
}

//From36to10
//36进制转10进制
func From36to10(str string) (n float64) {
	dict := "0RGJKD43SM8NL2AYBZQ7WX69ECH5U1VOIPFT"
	length := len(str)
	for i := 0; i < length; i++ {
		char := str[i : i+1]
		pos := float64(strings.Index(dict, char))
		n += pos * math.Pow(36, float64(length-i-1))
	}
	return
}

// KeyInMap 模仿php的array_key_exists,判断是否存在map中
func KeyInMap(key string, m map[string]interface{}) bool {
	_, ok := m[key]
	if ok {
		return true
	}
	return false
}

// InArrayForString 模仿php的in_array,判断是否存在string数组中
func InArrayForString(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

// InArrayForInt 模仿php的in_array,判断是否存在int数组中
func InArrayForInt(items []int, item int) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

// PasswordHash php的函数password_hash
func PasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// PasswordVerify php的函数password_verify
func PasswordVerify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// IntArrToStringArr int数组转string数组
func IntArrToStringArr(arr []int) []string {
	var stringArr []string
	for _, v := range arr {
		stringArr = append(stringArr, strconv.Itoa(v))
	}
	return stringArr
}

// GetMd5String 对字符串进行MD5哈希
func GetMd5String(str string) (string, error) {
	t := md5.New()
	if _, err := io.WriteString(t, str); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", t.Sum(nil)), nil
}

// GetSha1String 对字符串进行SHA1哈希
func GetSha1String(str string) (string, error) {
	t := sha1.New()
	if _, err := io.WriteString(t, str); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", t.Sum(nil)), nil
}

// Decimal 四舍五入 dec 保留精度
func Decimal(value float64, dec int) float64 {
	format := fmt.Sprintf("%%.%df", dec)
	value, _ = strconv.ParseFloat(fmt.Sprintf(format, value), 64)
	return value
}
