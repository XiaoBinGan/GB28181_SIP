package common

/*
Package common provides a logging utility that utilizes the Zap logger library
for structured and performant logging. It includes functions for logging at
different log levels and is configured to write log entries to a file using
the Lumberjack log rotation mechanism.

Author: wujiahao

Initial Description:
This package sets up a structured logging system using Uber's Zap logger and
Lumberjack for log rotation. It allows you to log messages at different
severity levels, such as Debug, Info, Warn, Error, DPanic, and Fatal, and
supports both plain and formatted log messages. The log output is directed to
a file with rotation based on size, and each log entry includes a timestamp
in ISO8601 format. Additionally, caller information can be included in log
entries for debugging purposes.

Usage:
To use this logging utility, simply import the package and make calls to the
logging functions as needed. The logger is initialized with default
configuration, but you can customize it by modifying the init() function in
this package.
*/
import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	logger *zap.SugaredLogger
)

func init() {
	//log file name
	fileName := "logs/micro.log"
	writeSyncer := zapcore.AddSync(&lumberjack.Logger{
		Filename: fileName, //file name
		MaxSize:  521,      //the file max size *MB
		//MaxAge:     0,		//the destroy time
		MaxBackups: 0,    //the max back up
		LocalTime:  true, //start local time
		Compress:   true, //is zip
	})
	//encode
	encoder := zap.NewProductionEncoderConfig()
	//time format
	encoder.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		//encoder
		zapcore.NewJSONEncoder(encoder),
		writeSyncer,
		zap.NewAtomicLevelAt(zap.DebugLevel))
	log := zap.New(
		core,
		zap.AddCaller(),
		zap.AddCallerSkip(1)) //有时我们稍微封装了一下记录日志的方法，但是我们希望输出的文件名和行号是调用封装函数的位置。这时可以使用zap.AddCallerSkip(skip int)向上跳 1 层：
	logger = log.Sugar()
}
func Debug(args ...interface{}) {
	logger.Debug(args)
}
func Debugf(template string, args ...interface{}) {
	logger.Debugf(template, args)
}

func Info(args ...interface{}) {
	logger.Info(args...)
}
func Infof(template string, arg ...interface{}) {
	logger.Infof(template, arg...)
}
func Warn(args ...interface{}) {
	logger.Warn(args...)
}
func Warnf(template string, args ...interface{}) {
	logger.Warnf(template, args...)
}
func Error(args ...interface{}) {
	logger.Error(args...)
}
func Errorf(template string, args ...interface{}) {
	logger.Errorf(template, args)
}
func DPanic(args ...interface{}) {
	logger.DPanic(args...)
}
func DPanicf(template string, args ...interface{}) {
	logger.DPanicf(template, args...)
}
func Fatal(args ...interface{}) {
	logger.Fatal(args...)
}
func FatalF(tempalte string, args ...interface{}) {
	logger.Fatalf(tempalte, args...)
}
