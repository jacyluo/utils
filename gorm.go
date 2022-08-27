package utils

import (
	"errors"
	"gorm.io/gorm"
)

type SqlRes struct {
	Sql         string
	AffectedNum int64
}

func Transaction(db *gorm.DB, ptr *[]SqlRes) error {
	tx := db.Begin()
	arrSql := *ptr
	for i := 0; i < len(arrSql); i++ {
		if result := tx.Exec(arrSql[i].Sql); result.Error != nil {
			tx.Rollback()
			return result.Error
		} else {
			if arrSql[i].AffectedNum != 0 {
				n := arrSql[i].AffectedNum
				if (n < 0 && result.RowsAffected == 0) || (n > 0 && n != result.RowsAffected) {
					tx.Rollback()
					return errors.New(arrSql[i].Sql + " rows affected invalid")
				}
			}
		}
	}
	tx.Commit()
	return nil
}
