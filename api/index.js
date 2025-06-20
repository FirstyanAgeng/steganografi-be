const express = require("express");
const multer = require("multer");
const sharp = require("sharp");
const crypto = require("crypto");
const AdmZip = require("adm-zip");
const cors = require("cors");
const pino = require("pino");
const pinoHttp = require("pino-http");

// Load environment variables
require("dotenv").config();

const app = express();
const logger = pino({ level: "info" });
const httpLogger = pinoHttp({ logger });

// --- Konfigurasi ---
const PORT = process.env.PORT || 5000;
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const EOF_MARKER = "1111111111111110";
const DATA_SEPARATOR = "||";
const AES_ALGORITHM = "aes-128-cbc";
const IV_LENGTH = 16; // Untuk AES, panjang IV adalah 16 byte

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(httpLogger);

// Multer setup untuk memproses file di memori
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const validTypes = ["image/jpeg", "image/png", "image/jpg"];
    if (validTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only jpg, jpeg, or png files are allowed"), false);
    }
  },
});

// --- Fungsi Helper ---

function currentDatetime() {
  return new Date().toISOString();
}

function encryptAES128(key, data) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + encrypted;
}

function decryptAES128(key, encryptedDataHex) {
  try {
    const iv = Buffer.from(encryptedDataHex.slice(0, IV_LENGTH * 2), "hex");
    const encryptedText = encryptedDataHex.slice(IV_LENGTH * 2);
    const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    logger.error(`Decryption error: ${error.message}`);
    if (error.message.includes("bad decrypt")) {
      throw new Error("Wrong decryption key.");
    }
    throw new Error("Failed to decrypt data. It might be corrupted.");
  }
}

async function calculateCapacity(imageBuffer) {
  const { width, height } = await sharp(imageBuffer).metadata();
  const totalBits = width * height * 3; // Gunakan 3 channel (RGB) untuk konsistensi
  return Math.floor(totalBits / 8) - 128; // Buffer keamanan 128 byte
}

async function hideDataInImage(
  imageBuffer,
  fileName,
  fileBuffer,
  textData,
  key
) {
  let dataToHide = "";
  if (fileName && fileBuffer) {
    dataToHide += `FILE:${fileName}:${fileBuffer.toString(
      "base64"
    )}${DATA_SEPARATOR}`;
  }
  if (textData) {
    dataToHide += `TEXT:${textData}${DATA_SEPARATOR}`;
  }
  if (!dataToHide) throw new Error("No data to hide");

  const encryptedData = encryptAES128(key, dataToHide);

  let binaryData = "";
  for (let i = 0; i < encryptedData.length; i++) {
    binaryData += encryptedData.charCodeAt(i).toString(2).padStart(8, "0");
  }
  binaryData += EOF_MARKER;

  const capacity = await calculateCapacity(imageBuffer);
  if (Math.ceil(binaryData.length / 8) > capacity) {
    throw new Error(
      `Data is too large for the image. Required: ${Math.ceil(
        binaryData.length / 8
      )} bytes, Available: ${capacity} bytes`
    );
  }

  const image = sharp(imageBuffer).ensureAlpha();
  const { data, info } = await image
    .raw()
    .toBuffer({ resolveWithObject: true });

  let dataIndex = 0;
  for (let i = 0; i < data.length && dataIndex < binaryData.length; i++) {
    if ((i + 1) % info.channels !== 0) {
      data[i] = (data[i] & 0xfe) | parseInt(binaryData[dataIndex], 2);
      dataIndex++;
    }
  }

  return sharp(data, {
    raw: { width: info.width, height: info.height, channels: info.channels },
  })
    .png({ quality: 100, compressionLevel: 0 })
    .toBuffer();
}

async function extractDataFromImage(imageBuffer, key) {
  const { data, info } = await sharp(imageBuffer)
    .raw()
    .toBuffer({ resolveWithObject: true });

  let binaryData = "";
  const eofRegex = new RegExp(EOF_MARKER);

  for (let i = 0; i < data.length; i++) {
    if ((i + 1) % info.channels !== 0) {
      binaryData += (data[i] & 1).toString();
    }
    if (i > 200 && i % 8 === 0) {
      if (eofRegex.test(binaryData)) break;
    }
  }

  const eofIndex = binaryData.indexOf(EOF_MARKER);
  if (eofIndex === -1)
    throw new Error("No hidden data found or data is corrupted.");

  let relevantBinary = binaryData.slice(0, eofIndex);
  let encryptedData = "";
  for (let i = 0; i < relevantBinary.length; i += 8) {
    const byte = relevantBinary.slice(i, i + 8);
    if (byte.length === 8) {
      encryptedData += String.fromCharCode(parseInt(byte, 2));
    }
  }

  const decryptedData = decryptAES128(key, encryptedData);
  const extracted = { files: [], text: "" };
  const items = decryptedData.split(DATA_SEPARATOR);

  items.forEach((item) => {
    if (item.startsWith("FILE:")) {
      const [, fileName, base64Data] = item.split(":", 3);
      if (fileName && base64Data) {
        extracted.files.push({
          name: fileName,
          data: Buffer.from(base64Data, "base64"),
        });
      }
    } else if (item.startsWith("TEXT:")) {
      extracted.text = item.slice(5);
    }
  });

  if (extracted.files.length === 0 && !extracted.text) {
    throw new Error("No valid data found after decryption.");
  }
  return extracted;
}

// --- Middleware Validasi ---
const validateKey = (req, res, next) => {
  const { key } = req.body;
  if (!key) {
    return res.status(400).json({ message: "Encryption key is required" });
  }
  if (key.length !== 16) {
    return res
      .status(400)
      .json({ message: "Key must be exactly 16 characters long" });
  }
  req.keyBuffer = Buffer.from(key, "utf8");
  next();
};

// --- Rute ---
app.post(
  "/encode",
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "file", maxCount: 1 },
  ]),
  validateKey,
  async (req, res, next) => {
    try {
      if (!req.files || !req.files.image) {
        return res.status(400).json({ message: "Image file is required" });
      }
      const { text } = req.body;
      const file = req.files.file ? req.files.file[0] : null;

      if (!text && !file) {
        return res
          .status(400)
          .json({ message: "Either text or a file must be provided" });
      }

      const startTime = Date.now();
      const imageBuffer = req.files.image[0].buffer;

      const encodedImageBuffer = await hideDataInImage(
        imageBuffer,
        file ? file.originalname : null,
        file ? file.buffer : null,
        text,
        req.keyBuffer
      );
      const processTime = Date.now() - startTime;
      const outputFilename = `encoded_${Date.now()}.png`;

      res.set({
        "Content-Type": "image/png",
        "Content-Disposition": `attachment; filename="${outputFilename}"`,
      });

      logger.info(
        {
          processTime,
          originalSize: imageBuffer.length,
          encodedSize: encodedImageBuffer.length,
        },
        "Image encoded successfully"
      );

      res.status(200).send(encodedImageBuffer);
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/decode",
  upload.single("image"),
  validateKey,
  async (req, res, next) => {
    try {
      if (!req.file) {
        return res
          .status(400)
          .json({ message: "Image file to decode is required" });
      }
      const startTime = Date.now();
      const extractedData = await extractDataFromImage(
        req.file.buffer,
        req.keyBuffer
      );
      const processTime = Date.now() - startTime;

      if (extractedData.files.length > 0) {
        const zip = new AdmZip();
        if (extractedData.text) {
          zip.addFile(
            "hidden_text.txt",
            Buffer.from(extractedData.text, "utf8")
          );
        }
        extractedData.files.forEach((file) => {
          zip.addFile(file.name, file.data);
        });

        const zipBuffer = zip.toBuffer();
        const zipFilename = `decoded_${Date.now()}.zip`;

        res.set({
          "Content-Type": "application/zip",
          "Content-Disposition": `attachment; filename="${zipFilename}"`,
        });
        return res.status(200).send(zipBuffer);
      }

      res.status(200).json({
        message: "Image decoded successfully",
        result: {
          processTime,
          extractedText: extractedData.text || "",
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK", version: "2.0.0" });
});

app.get("/", (req, res) => res.send("STEGANOGRAFI API Running"));

// --- Global Error Handler ---
app.use((error, req, res, next) => {
  logger.error(error, `Request error on ${req.method} ${req.originalUrl}`);
  const statusCode = error.message.includes("too large") ? 413 : 500;
  res.status(statusCode).json({
    message: `Operation failed: ${error.message}`,
  });
});

// ================= PERUBAHAN DI SINI =================
// HAPUS ATAU BERI KOMENTAR PADA BLOK app.listen
/*
app.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});
*/

// TAMBAHKAN BARIS INI UNTUK MENGEKSPOR APLIKASI ANDA
module.exports = app;
// ================= AKHIR DARI PERUBAHAN =================
