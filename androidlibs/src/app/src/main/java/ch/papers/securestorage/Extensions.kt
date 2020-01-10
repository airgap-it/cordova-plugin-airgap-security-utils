package ch.papers.securestorage

fun ByteArray.toHexString(): String = joinToString(separator = "") { String.format("%02x", it) }