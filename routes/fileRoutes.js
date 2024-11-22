import multer from 'multer';
import path from 'path';
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import User from '../models/User.js';
import File from '../models/File.js';
import {auth} from '../middlewares/auth.js'

const router = express.Router();

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        const extension = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + extension)
    }
});

const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: 50 * 1024 * 1024 
    }
});

router.post('/upload',auth, upload.single('doc'), async (req, res) => {
    const { recvId, senderId } = req.body;
    
    try {
        // Validate input
        if (!req.file || !recvId) {
            return res.status(400).json({
                success: false,
                message: "File and receiver Id are required"
            });
        }

        // Find receiver
        const receiver = await User.findById(recvId);
        if (!receiver) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const { publicKey, name } = receiver;

        // Generate cryptographically secure keys
        const aesKey = crypto.randomBytes(32);
        const aesIv = crypto.randomBytes(16);

        // File encryption
        const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, aesIv);
        const inputFile = fs.createReadStream(req.file.path);
        const encryptedFilePath = path.join('uploads/', `encrypted-${req.file.filename}`);
        const outputFile = fs.createWriteStream(encryptedFilePath);

        // Pipe and encrypt file
        const encryptedStream = inputFile.pipe(cipher).pipe(outputFile);

        await new Promise((resolve, reject) => {
            outputFile.on('finish', resolve);
            outputFile.on('error', reject);
        });

        // Encrypt AES key with receiver's public key
        const combinedKey = Buffer.concat([aesKey, aesIv]);
        const encryptedAesKey = crypto.publicEncrypt(publicKey, combinedKey);

        // Create file record
        const fileRecord = new File({
            fileName: `doc-${name}`,
            senderId,
            receiverId: recvId,
            filePath: encryptedFilePath,
            encryptedKey: encryptedAesKey.toString('base64'),
            aesKey: aesKey.toString('base64'),
            aesIv: aesIv.toString('base64')
        });

        await fileRecord.save();

        // Remove original unencrypted file
        fs.unlinkSync(req.file.path);

        return res.status(200).json({
            success: true,
            message: "File uploaded successfully",
            fileId: fileRecord._id
        });

    } catch (error) {
        console.error('File Upload Error:', error);
        return res.status(500).json({
            success: false,
            message: "Error in file upload",
            errorDetails: error.message
        });
    }
});

// File download route
router.get('/download/:fileId', auth,async (req, res) => {
    try {
        // Find file record
        const fileRecord = await File.findById(req.params.fileId);
        if (!fileRecord) {
            return res.status(404).json({
                success: false,
                message: "File not found"
            });
        }

        const {currentUser} = req.user.id; 
        if (currentUser._id.toString() !== fileRecord.receiverId.toString()) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized download"
            });
        }

        // Retrieve user's private key
        const user = await User.findById(currentUser._id);
        if (!user || !user.privateKey) {
            return res.status(401).json({
                success: false,
                message: "No decryption key available"
            });
        }

        // Decrypt AES key
        const encryptedKey = Buffer.from(fileRecord.encryptedKey, 'base64');
        const decryptedCombinedKey = crypto.privateDecrypt(
            { 
                key: user.privateKey, 
                passphrase: '' 
            }, 
            encryptedKey
        );
        
        // Split decrypted key
        const aesKey = decryptedCombinedKey.slice(0, 32);
        const aesIv = decryptedCombinedKey.slice(32);

        // Decrypt file
        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, aesIv);
        const inputFile = fs.createReadStream(fileRecord.filePath);
        const decryptedFilePath = path.join('downloads/', `decrypted-${fileRecord.fileName}`);
        const outputFile = fs.createWriteStream(decryptedFilePath);

        inputFile.pipe(decipher).pipe(outputFile);

        await new Promise((resolve, reject) => {
            outputFile.on('finish', resolve);
            outputFile.on('error', reject);
        });

        res.download(decryptedFilePath, fileRecord.fileName, (err) => {
            if (err) {
                console.error('Download Error:', err);
                fs.unlinkSync(decryptedFilePath);
            } else {
                fs.unlinkSync(decryptedFilePath);
            }
        });

    } catch (error) {
        console.error('File Download Error:', error);
        return res.status(500).json({
            success: false,
            message: "Error downloading file",
            errorDetails: error.message
        });
    }
});

export default router;