// ✅ Required to use Node.js runtime (not Edge)
export const config = {
    api: {
      bodyParser: false,
      externalResolver: true
    },
    runtime: "nodejs"
  }
  
  // ✅ Imports
  import type { NextApiRequest, NextApiResponse } from 'next'
  import formidable, { Fields, Files } from 'formidable'
  import fs from 'fs'
  import FormData from 'form-data'
  import axios from 'axios'
  import { ReadStream } from 'fs'
  
  // ✅ VirusTotal API Key
  const VT_API_KEY = "b58b611f623a6c534e265e7cde1c92f22c8bfa77858e7a295f884cd1d533f3a3"
  
  export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
  ) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' })
    }
  
    const form = formidable({ multiples: false })
  
    form.parse(req, async (_: any, fields: Fields, files: Files) => {
      try {
        const fileItem = files.file?.[0]
        if (!fileItem) {
          return res.status(400).json({ error: 'No file uploaded' })
        }
  
        const filePath = fileItem.filepath
        const fileName = fileItem.originalFilename || 'uploaded_file'
        const fileBuffer = fs.readFileSync(filePath)
  
        // ✅ Calculate SHA-256 hash
        const crypto = await import('crypto')
        const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex')
  
        // ✅ Step 1: Check if already in VirusTotal
        try {
          const check = await axios.get(`https://www.virustotal.com/api/v3/files/${fileHash}`, {
            headers: { 'x-apikey': VT_API_KEY }
          })
          return res.status(200).json({ found: true, result: check.data })
        } catch (err: any) {
          if (err.response?.status !== 404) {
            return res.status(500).json({ error: 'VirusTotal check failed', details: err.message })
          }
        }
  
        // ✅ Step 2: Upload to VirusTotal if not found
        const formData = new FormData()
        formData.append("file", fs.createReadStream(filePath) as ReadStream, fileName)
  
        const upload = await axios.post("https://www.virustotal.com/api/v3/files", formData, {
          headers: {
            'x-apikey': VT_API_KEY,
            ...formData.getHeaders()
          }
        })
  
        return res.status(200).json({
          found: false,
          upload: upload.data,
          hash: fileHash
        })
  
      } catch (error: any) {
        return res.status(500).json({ error: 'Internal Server Error', details: error.message })
      }
    })
  }