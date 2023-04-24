'use strict';

const stringify = require('json-stringify-deterministic');
const sortKeysRecursive = require('sort-keys-recursive');
const { Contract } = require('fabric-contract-api');
const { uploadFileBlock, downloadFileBlock } = require('./ipfs.js');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class IpfsSaveShare extends Contract {

    // 初始化合约
    async InitLedger(ctx) {
        const assets = [];

        for (const asset of assets) {
            asset.docType = 'asset';
            // example of how to write to world state deterministically
            // use convetion of alphabetic order
            // we insert data in alphabetic order using 'json-stringify-deterministic' and 'sort-keys-recursive'
            // when retrieving data, in any lang, the order of data will be the same and consequently also the corresonding hash
            await ctx.stub.putState(asset.ID, Buffer.from(stringify(sortKeysRecursive(asset))));
        }
    }

    /**
     * 公开共享型文件上传
     * @param {*} ctx 上下文对象
     * @param {*} fp 文件
     * @param {Boolean} ne 是否对文件地址加密
     * @param {String} password 加密密码，如果不加密则为任意值
     * @returns 信息
     */
    async UploadPublicShare(ctx, fp, ne, password) {

        var info = {};

        // 上传文件块
        const hash = await uploadFileBlock(fp);
        var Up = null;
        if (ne) {
            // 对文件地址加密
            encrypted = aes_encrypt(hash, password);
            Up = encrypted.encryptedText;
            info['iv'] = encrypted.iv;
        } else {
            Up = hash;
        }
        // 生成文件块的唯一识别码
        id = uuidv4();
        info['If'] = id;
        // 生成一个时间戳
        ts = timestamp();

        const exists = await this.AssetExists(ctx, id);
        if (exists) {
            throw new Error(`The asset ${id} already exists`);
        }

        const asset = {
            ID: id,
            class: 'public',
            ne: ne,
            timestamp: ts,
            Up: Up,
        };
        // we insert data in alphabetic order using 'json-stringify-deterministic' and 'sort-keys-recursive'
        await ctx.stub.putState(id, Buffer.from(stringify(sortKeysRecursive(asset))));
        return info;
    }

    /**
     * 公开共享型文件下载
     * @param {*} ctx 
     * @param {*} id 文件块的唯一识别码
     * @param {String} iv AES加密的初始化向量（16字节），如果不加密则为任意值
     * @param {String} password 加密密码，如果不加密则为任意值
     * @returns 
     */
    async DownloadPublicShare(ctx, id, iv, password) {

        const asset = await this.ReadAsset(ctx, id);
        if (asset.class != 'public') {
            throw new Error(`The asset ${id} is not public`);
        }
        Kp = null;
        if (asset.ne) {
            // 对文件地址解密
            Kp = aes_decrypt(iv, asset.Up, password);
        } else {
            Kp = asset.Up;
        }
        return downloadFileBlock(Kp);
    }

    // AssetExists returns true when asset with given ID exists in world state.
    async AssetExists(ctx, id) {
        const assetJSON = await ctx.stub.getState(id);
        return assetJSON && assetJSON.length > 0;
    }

    // ReadAsset returns the asset stored in the world state with given id.
    // 这里我实现的和官方示例代码有一丝不同，我返回了json格式的数据
    async ReadAsset(ctx, id) {
        const assetJSON = await ctx.stub.getState(id); // get the asset from chaincode state
        if (!assetJSON || assetJSON.length === 0) {
            throw new Error(`The asset ${id} does not exist`);
        }
        return assetJSON;
    }
}

// AES加密函数
function aes_encrypt(text, password) {
    const iv = crypto.randomBytes(16); // 生成一个随机的16字节的初始化向量
    const key = crypto.scryptSync(password, 'salt', 32); // 通过密码生成32字节的密钥

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv); // 创建加密器
    let encrypted = cipher.update(text, 'utf8', 'hex'); // 加密输入的明文
    encrypted += cipher.final('hex');

    return {
        iv: iv.toString('hex'), // 返回加密时使用的初始化向量，转换为16进制字符串
        encryptedText: encrypted // 返回加密后的密文，转换为16进制字符串
    };
}

// AES解密函数
function aes_decrypt(iv, encryptedText, password) {
    const key = crypto.scryptSync(password, 'salt', 32); // 通过密码生成32字节的密钥
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex')); // 创建解密器，传入初始化向量

    let decrypted = decipher.update(encryptedText, 'hex', 'utf8'); // 解密输入的密文
    decrypted += decipher.final('utf8');

    return decrypted; // 返回解密后的明文
}

function timestamp() {
    return new Date().getTime().toString();
}

/**
 * 展示信息
 * @param {JSON} info 
 */
function showInfo(info) {
    console.log(info);
}

module.exports = IpfsSaveShare;