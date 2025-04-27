package utils

import (
	"errors"
	"fmt"
	vd "github.com/bytedance/go-tagexpr/v2/validator"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	regIDCard()
	regCn()
	regEn()
	regInt()
	regFloat()
	regUrl()
	regDate()
	regDatetime()
	regPhone()
}

/*
*
检查15、18位的身份证号是否有效
验证省份、出生日期是否大于当前时间
18检验效验码
*/
func regIDCard() {
	vd.RegFunc("chkIDCard", func(args ...interface{}) error {
		if len(args) == 0 {
			return errors.New("invalid IDCard no")
		}
		s, ok := args[0].(string)
		if !ok {
			return errors.New("invalid IDCard no")
		}
		if ok = isIDCard(s); ok {
			return nil
		}
		return errors.New("invalid IDCard no")
	}, true)
}

func isIDCard(id string) bool {
	id = strings.ToUpper(id)
	if len(id) != 15 && len(id) != 18 {
		return false
	}
	r := regexp.MustCompile("(\\d{15})|(\\d{17}(\\d|X))")
	if !chkProv(id) {
		return false
	}
	if !r.MatchString(id) {
		return false
	}
	if len(id) == 15 {
		tm2, _ := time.Parse("01/02/2006", string([]byte(id)[8:10])+"/"+string([]byte(id)[10:12])+"/"+"19"+string([]byte(id)[6:8]))
		if tm2.Unix() >= time.Now().Unix() {
			return false
		}
		return true
	} else {
		tm2, _ := time.Parse("01/02/2006", string([]byte(id)[10:12])+"/"+string([]byte(id)[12:14])+"/"+string([]byte(id)[6:10]))
		if tm2.Unix() >= time.Now().Unix() {
			return false
		}
		// 检验18位身份证的校验码是否正确。
		// 校验位按照ISO 7064:1983.MOD 11-2的规定生成，X可以认为是数字10。
		arrInt := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
		arrCh := []string{"1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"}
		sign := 0
		for k, v := range arrInt {
			intTemp, _ := strconv.Atoi(string([]byte(id)[k : k+1]))
			sign += intTemp * v
		}
		n := sign % 11
		valNum := arrCh[n]
		if valNum != string([]byte(id)[17:18]) {
			return false
		}
		return true
	}
}

func chkProv(id string) bool {
	prov, _ := strconv.Atoi(id[0:2])
	provArr := []int{11, 12, 13, 14, 15, 21, 22, 23, 31, 32, 33, 34, 35, 36, 37, 41, 42, 43, 44, 45, 46, 50, 51, 52, 53, 54, 61, 62, 63, 64, 65, 71, 81, 82, 91}
	var min, mid, max int
	min = 0
	max = len(provArr) - 1

	for {
		mid = (min + max) / 2
		if provArr[mid] == prov {
			return true
		} else if prov < provArr[mid] {
			max = mid - 1
		} else if prov > provArr[mid] {
			min = mid + 1
		}
		if min > max {
			return false
		}
	}
}

/*
*
检查是否为空，或全都是汉字，允许长度范围 [min,max]
参数：
str string
minLen int
maxLen int
*/
func regCn() {
	vd.RegFunc("chkCn", func(args ...interface{}) error {
		var min, max int = -1, 0
		size := len(args)

		if size == 0 {
			return errors.New("invalid parameter number")
		}
		s, ok := args[0].(string)
		if !ok {
			return errors.New("invalid cn chars")
		}

		if size > 1 {
			tmp, ok := args[1].(float64)
			if ok {
				min = int(tmp)
			}
		}
		if size > 2 {
			tmp, ok := args[2].(float64)
			if ok {
				max = int(tmp)
			}
		}

		pattern := "^[\\p{Han}]"
		if min > -1 {
			pattern += "{" + strconv.Itoa(min) + ","
			if max > 0 && max >= min {
				pattern += strconv.Itoa(max)
			}
			pattern += "}$"
		} else {
			pattern += "*$"
		}

		cnRegexp := regexp.MustCompile(pattern)
		if matched := cnRegexp.MatchString(s); matched {
			return nil
		}
		return errors.New("invalid cn chars")
	})
}

/*
*
检查是否为空，或全都是英文字符 允许长度范围[min,max]
参数：
str string
minLen int 选填
maxLen int 选填
*/
func regEn() {
	vd.RegFunc("chkEn", func(args ...interface{}) error {
		var min, max int = -1, 0
		size := len(args)

		if size == 0 {
			return errors.New("invalid parameter number")
		}
		s, ok := args[0].(string)
		if !ok {
			return errors.New("invalid en chars")
		}

		if size > 1 {
			tmp, ok := args[1].(float64)
			if ok {
				min = int(tmp)
			}
		}
		if size > 2 {
			tmp, ok := args[2].(float64)
			if ok {
				max = int(tmp)
			}
		}

		pattern := "^\\w"
		if min > -1 {
			pattern += "{" + strconv.Itoa(min) + ","
			if max > 0 && max >= min {
				pattern += strconv.Itoa(max)
			}
			pattern += "}$"
		} else {
			pattern += "*$"
		}

		cnRegexp := regexp.MustCompile(pattern)
		if matched := cnRegexp.MatchString(s); matched {
			return nil
		}
		return errors.New("invalid en chars")
	})
}

/*
*
检查是否为有效整数 允许范围[min,max]
参数：
value int
min int 选填
max int 选填
*/
func regInt() {
	vd.RegFunc("chkInt", func(args ...interface{}) error {
		var val int
		var min, max int
		size := len(args)

		if size == 0 {
			return errors.New("invalid parameter number")
		}
		value, ok := args[0].(float64)
		if !ok {
			return errors.New("invalid parameter int")
		}
		str := fmt.Sprintf("%f", value)   //采用浮点数，而不要科学计数法
		str = strings.TrimRight(str, "0") // 去除小数点后的无效0
		str = strings.TrimRight(str, ".") // 去除最后的小数点
		pos := strings.Index(str, ".")
		if pos >= 0 {
			//fmt.Println("不是有效的整数")
			return errors.New("invalid parameter int")
		}

		val = int(value)
		if size > 1 {
			tmp, ok := args[1].(float64)
			if ok {
				min = int(tmp)
				if val < min {
					//fmt.Println("val=",val,";min=",min)
					return errors.New("invalid parameter int")
				}
			}
		}
		if size > 2 {
			tmp, ok := args[2].(float64)
			if ok {
				max = int(tmp)
				if val > max {
					return errors.New("invalid parameter int")
				}
			}
		}
		return nil
	})
}

/*
*
检查是否为有效浮点数 允许范围[min,max]
参数：
value float64
min float64 选填
max float64 选填
precision int 小数点后位数 选填
*/
func regFloat() {
	vd.RegFunc("chkFloat", func(args ...interface{}) error {
		var val, min, max, tmp float64
		var ok bool
		var size, precision int
		size = len(args)

		//fmt.Printf("type is %T",args[0])

		if size == 0 {
			return errors.New("invalid parameter number")
		}
		val, ok = args[0].(float64)
		if !ok {
			return errors.New("invalid parameter float")
		}
		if size > 1 {
			min, ok = args[1].(float64)
			if ok && val < min {
				return errors.New("invalid parameter float")
			}
		}
		if size > 2 {
			max, ok = args[2].(float64)
			//fmt.Println("max=",max,";ok=",ok,";val=",val)
			if ok && val > max {
				return errors.New("invalid parameter float")
			}
		}

		//fmt.Printf("val=%f",val)

		//验证小数精度
		if size > 3 {
			tmp, ok = args[3].(float64)
			if ok {
				precision = int(tmp)
				if precision > 0 {
					str := fmt.Sprintf("%f", val)     //采用浮点数，而不要科学计数法
					str = strings.TrimRight(str, "0") // 去除小数点后的无效0
					pos := strings.Index(str, ".")
					if len(str[pos+1:]) > precision {
						return errors.New("invalid precision")
					}
				}
			}
		}
		return nil
	})
}

/*
*
检查是否为有效网址
参数：
value string
*/
func regUrl() {
	vd.RegFunc("chkUrl", func(args ...interface{}) error {
		var size int
		size = len(args)
		if size == 0 {
			return errors.New("invalid parameter number")
		}
		s, ok := args[0].(string)
		if !ok {
			return errors.New("invalid parameter Url")
		}
		pattern := "^https?://[\\w\\-]+(\\.[\\w\\-]+)+([\\w\\-\\.,@?^=%&:/~\\+#]*[\\w\\-\\@?^=%&\\/~\\+#])?$"

		urlRegexp := regexp.MustCompile(pattern)
		if matched := urlRegexp.MatchString(s); matched {
			return nil
		}
		return errors.New("invalid Url")
	})
}

/*
*
检查是否为有效日期格式
参数：
value string
*/
func regDate() {
	vd.RegFunc("chkDate", func(args ...interface{}) error {
		var size int
		size = len(args)
		if size == 0 {
			return errors.New("invalid parameter number")
		}
		s, ok := args[0].(string)
		if !ok {
			return errors.New("invalid parameter date")
		}
		var format, split string
		if strings.Index(s, "-") > 0 {
			split = "-"
		} else if strings.Index(s, "/") > 0 {
			split = "/"
		}
		format = fmt.Sprintf("2006%s01%s02", split, split)
		if _, ok := time.Parse(format, s); ok != nil {
			return errors.New("invalid Date")
		}
		return nil
	})
}

/*
*
检查是否为有效时间
参数：
value string
*/
func regDatetime() {
	vd.RegFunc("chkDatetime", func(args ...interface{}) error {
		var size int
		size = len(args)
		if size == 0 {
			return errors.New("invalid parameter number")
		}
		s, ok := args[0].(string)
		if !ok {
			return errors.New("invalid parameter datetime")
		}
		var format, split string
		if strings.Index(s, "-") > 0 {
			split = "-"
		} else if strings.Index(s, "/") > 0 {
			split = "/"
		} else {
			return errors.New("invalid Datetime")
		}

		format = fmt.Sprintf("2006%s01%s02 15:04", split, split)
		arr := strings.Split(s, ":")
		if len(arr) == 3 {
			format += ":05"
		}
		if _, ok := time.Parse(format, s); ok != nil {
			return errors.New("invalid Datetime")
		}
		return nil
	})
}

/*
*
检查是否为有效手机号
参数：
value string
*/
func regPhone() {
	vd.RegFunc("chkPhone", func(args ...interface{}) error {
		var size int
		size = len(args)
		if size != 1 {
			return errors.New("invalid parameter number")
		}
		s, ok := args[0].(string)
		if !ok {
			return errors.New("invalid parameter phone")
		}
		pattern := "^1[3456789]\\d{9}$"

		urlRegexp := regexp.MustCompile(pattern)
		if matched := urlRegexp.MatchString(s); matched {
			return nil
		}
		return errors.New("invalid phone")
	})
}
