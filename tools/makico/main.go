// 将 JPG/PNG 转换为 Windows ICO（内嵌 PNG 格式，支持 256/48/32/16 四尺寸）
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/draw"
	_ "image/jpeg"
	"image/png"
	"os"

	xdraw "golang.org/x/image/draw"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "用法: makico <input.jpg> <output.ico>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "打开图片失败:", err)
		os.Exit(1)
	}
	src, _, err := image.Decode(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "解码图片失败:", err)
		os.Exit(1)
	}

	sizes := []int{256, 48, 32, 16}
	var pngDataList [][]byte
	for _, sz := range sizes {
		dst := image.NewRGBA(image.Rect(0, 0, sz, sz))
		xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
		var buf bytes.Buffer
		if err := png.Encode(&buf, dst); err != nil {
			fmt.Fprintln(os.Stderr, "PNG 编码失败:", err)
			os.Exit(1)
		}
		pngDataList = append(pngDataList, buf.Bytes())
	}

	out, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "创建 ICO 失败:", err)
		os.Exit(1)
	}
	defer out.Close()

	w := func(v interface{}) { binary.Write(out, binary.LittleEndian, v) }

	// ICO 文件头
	w(uint16(0)) // 保留
	w(uint16(1)) // 类型=ICO
	w(uint16(len(sizes)))

	dataOffset := uint32(6 + len(sizes)*16)
	for i, sz := range sizes {
		iconSz := uint8(sz)
		if sz >= 256 {
			iconSz = 0
		}
		w(iconSz)                           // 宽
		w(iconSz)                           // 高
		w(uint8(0))                         // 调色板色数
		w(uint8(0))                         // 保留
		w(uint16(1))                        // 颜色平面数
		w(uint16(32))                       // 位深
		w(uint32(len(pngDataList[i])))      // 数据大小
		w(dataOffset)                       // 数据偏移
		dataOffset += uint32(len(pngDataList[i]))
	}
	for _, data := range pngDataList {
		out.Write(data)
	}

	fmt.Println("ICO 已生成:", os.Args[2])
}
