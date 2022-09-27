package utils

import (
	"errors"
	"fmt"
	"gorm.io/gorm"
)

type SqlRes struct {
	Sql         string
	AffectedNum int64 // 影响记录数，-1只要大于0；0忽略该参数；正整数为具体影响记录数
}

type FyTransaction struct {
	ArrSql []SqlRes
}

func (e *FyTransaction) Append(sql *string, num int64) {
	e.ArrSql = append(e.ArrSql, SqlRes{
		Sql:         *sql,
		AffectedNum: num,
	})
}

func (e *FyTransaction) String() (str string) {
	for i := 0; i < len(e.ArrSql); i++ {
		str += fmt.Sprintf("%s;\t%v\n", e.ArrSql[i].Sql, e.ArrSql[i].AffectedNum)
	}
	return
}

func (e *FyTransaction) Run(db *gorm.DB) error {
	tx := db.Begin()
	arrSql := e.ArrSql
	for i := 0; i < len(arrSql); i++ {
		if result := tx.Exec(arrSql[i].Sql); result.Error != nil {
			tx.Rollback()
			return result.Error
		} else {
			if arrSql[i].AffectedNum != 0 {
				n := arrSql[i].AffectedNum
				if (n < 0 && result.RowsAffected == 0) || (n > 0 && n != result.RowsAffected) {
					tx.Rollback()
					return errors.New(arrSql[i].Sql + "; error: rows affected invalid")
				}
			}
		}
	}
	tx.Commit()
	return nil
}
