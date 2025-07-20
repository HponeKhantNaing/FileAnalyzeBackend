import type { NextApiRequest, NextApiResponse } from 'next'
import formidable, { Fields, Files } from 'formidable'
import fs from 'fs'
import FormData from 'form-data'
import axios from 'axios'
import path from 'path'
import { ReadStream } from 'fs'

// Disable default body parsing so formidable can handle it
export const config = {
  api: {
    bodyParser: false
  }
}

// VirusTotal API Key
const VT_API_KEY = "b58b611f623a6c534e265e7cde1c92f22c8bfa77858e7a295f884cd1d533f3a3"

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" })
  }

  const form = formidable({ multiples: false })

  form.parse(req, async (_: any, fields: Fields, files: Files) => {
    try {
      const fileItem = files.file?.[0]
      if (!fileItem) {
        return res.status(400).json({ error: "No file uploaded" })
      }

      const filePath = fileItem.filepath
      const fileName = fileItem.originalFilename || "uploaded_file"
      const fileBuffer = fs.readFileSync(filePath)

      // SHA-256 hash calculation
      const crypto = await import("crypto")
      const fileHash = crypto.createHash("sha256").update(fileBuffer).digest("hex")

      // First check if file hash already exists in VirusTotal
      try {
        const response = await axios.get(
          `https://www.virustotal.com/api/v3/files/${fileHash}`,
          {
            headers: {
              "x-apikey": VT_API_KEY
            }
          }
        )
        return res.status(200).json({ found: true, result: response.data })
      } catch (err: any) {
        if (err.response?.status !== 404) {
          return res.status(500).json({ error: "VirusTotal API error", detail: err.message })
        }
      }

      // If file is not found in VirusTotal, upload it
      const formData = new FormData()
      formData.append("file", fs.createReadStream(filePath) as ReadStream, fileName)

      const uploadResponse = await axios.post(
        "https://www.virustotal.com/api/v3/files",
        formData,
        {
          headers: {
            "x-apikey": VT_API_KEY,
            ...formData.getHeaders()
          }
        }
      )

      return res.status(200).json({
        found: false,
        upload: uploadResponse.data,
        hash: fileHash
      })
    } catch (error: any) {
      return res.status(500).json({ error: "Internal Server Error", detail: error.message })
    }
  })
}