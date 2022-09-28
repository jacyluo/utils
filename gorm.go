package utils

import (
	"errors"
	"fmt"
	"gorm.io/gorm"
)

type SqlRes struct {
	Sql          string
	AffectedRows int64 // 影响记录数，-1只要大于0；0忽略该参数；正整数为具体影响记录数
}

type FyTransaction struct {
	ArrSql []SqlRes
}

func (e *FyTransaction) Append(sql *string, rows int64) {
	e.ArrSql = append(e.ArrSql, SqlRes{
		Sql:          *sql,
		AffectedRows: rows,
	})
}

func (e *FyTransaction) String() (str string) {
	for i := 0; i < len(e.ArrSql); i++ {
		str += fmt.Sprintf("%s;\t%v\n", e.ArrSql[i].Sql, e.ArrSql[i].AffectedRows)
	}
	return
}

func (e *FyTransaction) Run(db *gorm.DB) error {
	tx := db.Begin()
	for i := 0; i < len(e.ArrSql); i++ {
		if result := tx.Exec(e.ArrSql[i].Sql); result.Error != nil {
			tx.Rollback()
			return result.Error
		} else {
			if e.ArrSql[i].AffectedRows != 0 {
				n := e.ArrSql[i].AffectedRows
				if (n < 0 && result.RowsAffected == 0) || (n > 0 && n != result.RowsAffected) {
					tx.Rollback()
					return errors.New(e.ArrSql[i].Sql + "; error: rows affected invalid")
				}
			}
		}
	}
	tx.Commit()
	return nil
}
