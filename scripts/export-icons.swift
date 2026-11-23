#!/usr/bin/env swift
import AppKit
import Foundation

let scriptDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let iconsDir = scriptDir.deletingLastPathComponent().appendingPathComponent("extension/icons")
let svgURL = iconsDir.appendingPathComponent("icon.svg")

guard let svgData = try? Data(contentsOf: svgURL),
      let image = NSImage(data: svgData) else {
  fputs("Failed to load \(svgURL.path)\n", stderr)
  exit(1)
}

for size in [16, 32, 48, 128] {
  guard let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: size,
    pixelsHigh: size,
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
  ) else {
    exit(1)
  }

  rep.size = NSSize(width: size, height: size)
  NSGraphicsContext.saveGraphicsState()
  NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
  NSGraphicsContext.current?.imageInterpolation = .high
  image.draw(
    in: NSRect(x: 0, y: 0, width: size, height: size),
    from: .zero,
    operation: .copy,
    fraction: 1.0
  )
  NSGraphicsContext.restoreGraphicsState()

  guard let pngData = rep.representation(using: .png, properties: [:]) else {
    exit(1)
  }
  let outURL = iconsDir.appendingPathComponent("icon-\(size).png")
  try pngData.write(to: outURL)
  print("Exported \(outURL.path) (\(size)x\(size))")
}
