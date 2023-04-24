var crypto = require ('crypto');
var sha256 = crypto.createHash ('sha256');

const H = (data) => {
    sha256.update(data);
    return sha256.digest('hex');
}

// 上传文件块
/**
 * 上传文件块
 * @param {*} fileBlock 文件块
 * @returns 如果上传成功，返回文件块的哈希值，否则返回null
 */
const uploadFileBlock = async (fileBlock) => {
    
    // 对输入进行SHA256哈希
    const hash = H(fileBlock);

    return hash;
}

/**
 * 下载文件块
 * @param {String} hash 文件块的哈希值
 * @returns 
 */
const downloadFileBlock = async (hash) => {
    return true;
}

module.exports = {
    uploadFileBlock,
    downloadFileBlock
}