using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using MySql.Data.MySqlClient;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace DataMaskingApplication
{
    public partial class MainForm : Form
    {
        private string connectionString = "Server=localhost;Database=secure_data;Uid=root;Pwd=tuyen123;";
        private MySqlConnection connection;
        private TcpListener server;
        private bool isServerRunning = false;

        public MainForm()
        {
            InitializeComponent();
            InitializeDatabase();
            StartServer();
            LoadDataForTabs(); // Tải dữ liệu cho cả hai tab Quản lý và Gửi
        }

        private void InitializeDatabase()
        {
            try
            {
                connection = new MySqlConnection(connectionString);
                connection.Open();

                string createTableQuery = @"
                    CREATE TABLE IF NOT EXISTS sensitive_data (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        full_name VARCHAR(100),
                        email VARCHAR(100),
                        phone VARCHAR(20),
                        credit_card VARCHAR(19),
                        ssn VARCHAR(11),
                        address TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )";

                using (MySqlCommand cmd = new MySqlCommand(createTableQuery, connection))
                {
                    cmd.ExecuteNonQuery();
                }

                connection.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi kết nối cơ sở dữ liệu: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StartServer()
        {
            try
            {
                server = new TcpListener(IPAddress.Any, 8888);
                server.Start();
                isServerRunning = true;
                statusLabel.Text = "Server đang chạy trên port 8888...";
                Task.Run(() => ListenForClients());
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi khởi động server: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ListenForClients()
        {
            while (isServerRunning)
            {
                try
                {
                    TcpClient client = server.AcceptTcpClient();
                    NetworkStream stream = client.GetStream();
                    byte[] buffer = new byte[1024];
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    string jsonData = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    // Phân tích JSON
                    var data = JsonSerializer.Deserialize<Dictionary<string, string>>(jsonData);
                    string maskedData = data["masked"].Replace("\\n", "\n");
                    string encryptedData = data["encrypted"];

                    // Hiển thị dữ liệu nhận được dưới dạng bảng
                    this.Invoke((MethodInvoker)delegate
                    {
                        string key = txtKeyReceive.Text.Trim();
                        DataTable receivedTable = new DataTable();
                        receivedTable.Columns.Add("Field", typeof(string));
                        receivedTable.Columns.Add("Value", typeof(string));

                        if (!string.IsNullOrEmpty(key))
                        {
                            try
                            {
                                string decryptedData = EncryptionHelper.Decrypt(encryptedData, key);
                                // Kiểm tra xem dữ liệu giải mã có hợp lệ không
                                if (!string.IsNullOrEmpty(decryptedData) && decryptedData.Contains(": "))
                                {
                                    var decryptedLines = decryptedData.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                                    foreach (var line in decryptedLines)
                                    {
                                        var parts = line.Split(new[] { ": " }, 2, StringSplitOptions.None);
                                        if (parts.Length == 2)
                                        {
                                            receivedTable.Rows.Add(parts[0].Trim(), parts[1].Trim());
                                        }
                                    }
                                }
                                else
                                {
                                    throw new Exception("Dữ liệu giải mã không hợp lệ"); // Buộc vào catch để hiển thị maskedData
                                }
                            }
                            catch (Exception ex)
                            {
                                // Khi giải mã thất bại hoặc dữ liệu không hợp lệ, hiển thị dữ liệu che mặt nạ
                                var maskedLines = maskedData.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                                foreach (var line in maskedLines)
                                {
                                    var parts = line.Split(new[] { ": " }, 2, StringSplitOptions.None);
                                    if (parts.Length == 2)
                                    {
                                        receivedTable.Rows.Add(parts[0].Trim(), parts[1].Trim());
                                    }
                                }
                            }
                        }
                        else
                        {
                            // Nếu không nhập key, hiển thị dữ liệu che mặt nạ
                            var maskedLines = maskedData.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (var line in maskedLines)
                            {
                                var parts = line.Split(new[] { ": " }, 2, StringSplitOptions.None);
                                if (parts.Length == 2)
                                {
                                    receivedTable.Rows.Add(parts[0].Trim(), parts[1].Trim());
                                }
                            }
                        }

                        // Gán DataTable vào DataGridView
                        dataGridViewReceive.DataSource = null; // Xóa nguồn dữ liệu cũ
                        dataGridViewReceive.DataSource = receivedTable;

                        // Debug: Kiểm tra dữ liệu
                        if (receivedTable.Rows.Count == 0)
                        {
                            string debugMessage = $"Không có dữ liệu để hiển thị.\n" +
                                                 $"maskedData: '{maskedData}'\n" +
                                                 $"Số dòng sau Split: {maskedData.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries).Length}\n" +
                                                 $"Key nhập: '{key}'";
                            MessageBox.Show(debugMessage, "Debug", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        }
                    });

                    stream.Close();
                    client.Close();
                }
                catch (Exception ex)
                {
                    if (isServerRunning)
                    {
                        this.Invoke((MethodInvoker)delegate
                        {
                            MessageBox.Show("Lỗi khi nhận dữ liệu: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        });
                    }
                }
            }
        }

        private string MaskData(string data, string dataType)
        {
            if (string.IsNullOrEmpty(data))
                return data;

            switch (dataType)
            {
                case "name":
                    string[] nameParts = data.Split(' ');
                    for (int i = 0; i < nameParts.Length; i++)
                    {
                        if (nameParts[i].Length > 0)
                        {
                            nameParts[i] = nameParts[i][0] + new string('*', nameParts[i].Length - 1);
                        }
                    }
                    return string.Join(" ", nameParts);

                case "email":
                    int atIndex = data.IndexOf('@');
                    if (atIndex > 0)
                    {
                        string localPart = data.Substring(0, atIndex);
                        string domainPart = data.Substring(atIndex);
                        if (localPart.Length > 2)
                        {
                            return localPart.Substring(0, 2) + new string('*', localPart.Length - 2) + domainPart;
                        }
                    }
                    return data;

                case "phone":
                    if (data.Length > 4)
                    {
                        return new string('*', data.Length - 4) + data.Substring(data.Length - 4);
                    }
                    return data;

                case "credit_card":
                    string cleanedCard = new string(data.Where(char.IsDigit).ToArray());
                    if (cleanedCard.Length > 4)
                    {
                        return new string('*', cleanedCard.Length - 4) + cleanedCard.Substring(cleanedCard.Length - 4);
                    }
                    return data;

                case "ssn":
                    string cleanedSSN = new string(data.Where(char.IsDigit).ToArray());
                    if (cleanedSSN.Length > 4)
                    {
                        return "XXX-XX-" + cleanedSSN.Substring(cleanedSSN.Length - 4);
                    }
                    return data;

                case "address":
                    string[] addressParts = data.Split(',');
                    for (int i = 0; i < addressParts.Length - 1; i++)
                    {
                        string[] words = addressParts[i].Trim().Split(' ');
                        for (int j = 0; j < words.Length; j++)
                        {
                            if (j > 0 && j < words.Length - 1 && !int.TryParse(words[j], out _))
                            {
                                words[j] = new string('*', words[j].Length);
                            }
                        }
                        addressParts[i] = string.Join(" ", words);
                    }
                    return string.Join(", ", addressParts);

                default:
                    return data;
            }
        }

        private string ShuffleData(string data)
        {
            if (string.IsNullOrEmpty(data))
                return data;

            char[] characters = data.ToCharArray();
            Random random = new Random();
            for (int i = characters.Length - 1; i > 0; i--)
            {
                int j = random.Next(0, i + 1);
                char temp = characters[i];
                characters[i] = characters[j];
                characters[j] = temp;
            }
            return new string(characters);
        }

        private string SubstituteData(string originalData, string dataType)
        {
            Random random = new Random();
            switch (dataType)
            {
                case "name":
                    string[] firstNames = { "Nguyen", "Tran", "Le", "Pham", "Hoang", "Huynh", "Vo", "Dang", "Bui", "Do" };
                    string[] lastNames = { "An", "Binh", "Cuong", "Dung", "Huong", "Linh", "Minh", "Nam", "Phuong", "Tuan" };
                    return firstNames[random.Next(firstNames.Length)] + " " + lastNames[random.Next(lastNames.Length)];

                case "email":
                    string[] domains = { "example.com", "test.org", "sample.net", "demo.vn", "mail.xyz" };
                    string randomName = "user" + random.Next(1000, 9999);
                    return randomName + "@" + domains[random.Next(domains.Length)];

                case "phone":
                    return "09" + random.Next(10000000, 99999999).ToString();

                case "credit_card":
                    return "4" + random.Next(100, 999).ToString() + "-" +
                           random.Next(1000, 9999).ToString() + "-" +
                           random.Next(1000, 9999).ToString() + "-" +
                           random.Next(1000, 9999).ToString();

                case "ssn":
                    return random.Next(100, 999).ToString() + "-" +
                           random.Next(10, 99).ToString() + "-" +
                           random.Next(1000, 9999).ToString();

                case "address":
                    string[] streets = { "Nguyen Hue", "Le Loi", "Tran Hung Dao", "Pham Ngu Lao", "Vo Van Tan" };
                    string[] cities = { "Ho Chi Minh", "Ha Noi", "Da Nang", "Can Tho", "Hue" };
                    return random.Next(1, 100).ToString() + " " + streets[random.Next(streets.Length)] +
                           ", " + cities[random.Next(cities.Length)];

                default:
                    return originalData;
            }
        }

        private string PerturbData(string data)
        {
            if (string.IsNullOrEmpty(data) || !data.All(char.IsDigit))
                return data;

            Random random = new Random();
            char[] characters = data.ToCharArray();
            for (int i = 0; i < characters.Length; i++)
            {
                if (char.IsDigit(characters[i]))
                {
                    int digit = characters[i] - '0';
                    int noise = random.Next(-1, 2);
                    int newDigit = (digit + noise + 10) % 10;
                    characters[i] = (char)(newDigit + '0');
                }
            }
            return new string(characters);
        }

        private string ApplyMaskingMethod(string data, string dataType)
        {
            int method = Properties.Settings.Default.MaskingMethod;
            switch (method)
            {
                case 0: return MaskData(data, dataType);
                case 1: return ShuffleData(data);
                case 2: return SubstituteData(data, dataType);
                case 3: return PerturbData(data);
                default: return MaskData(data, dataType);
            }
        }

        private void LoadDataForTabs()
        {
            try
            {
                connection.Open();
                string query = "SELECT * FROM sensitive_data";
                MySqlDataAdapter adapter = new MySqlDataAdapter(query, connection);
                DataTable dataTable = new DataTable();
                adapter.Fill(dataTable);

                DataTable maskedTable = dataTable.Clone();
                foreach (DataRow row in dataTable.Rows)
                {
                    DataRow maskedRow = maskedTable.NewRow();
                    maskedRow["id"] = row["id"];
                    maskedRow["full_name"] = ApplyMaskingMethod(row["full_name"].ToString(), "name");
                    maskedRow["email"] = ApplyMaskingMethod(row["email"].ToString(), "email");
                    maskedRow["phone"] = ApplyMaskingMethod(row["phone"].ToString(), "phone");
                    maskedRow["credit_card"] = ApplyMaskingMethod(row["credit_card"].ToString(), "credit_card");
                    maskedRow["ssn"] = ApplyMaskingMethod(row["ssn"].ToString(), "ssn");
                    maskedRow["address"] = ApplyMaskingMethod(row["address"].ToString(), "address");
                    maskedRow["created_at"] = row["created_at"];
                    maskedTable.Rows.Add(maskedRow);
                }

                dataGridViewManage.DataSource = maskedTable; // Tải dữ liệu cho tab Quản lý
                dataGridViewSend.DataSource = maskedTable;   // Tải dữ liệu cho tab Gửi
                connection.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi tải dữ liệu: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }

        private void btnAddData_Click(object sender, EventArgs e)
        {
            AddDataForm addForm = new AddDataForm(connection);
            if (addForm.ShowDialog() == DialogResult.OK)
            {
                LoadDataForTabs();
            }
        }

        private void btnViewOriginal_Click(object sender, EventArgs e)
        {
            if (dataGridViewManage.SelectedRows.Count > 0)
            {
                int id = Convert.ToInt32(dataGridViewManage.SelectedRows[0].Cells["id"].Value);
                ViewOriginalDataForm viewForm = new ViewOriginalDataForm(connection, id);
                viewForm.ShowDialog();
            }
            else
            {
                MessageBox.Show("Vui lòng chọn một dòng để xem dữ liệu gốc.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void btnChangeMaskingMethod_Click(object sender, EventArgs e)
        {
            MaskingMethodForm methodForm = new MaskingMethodForm();
            if (methodForm.ShowDialog() == DialogResult.OK)
            {
                LoadDataForTabs();
            }
        }

        private void btnSendData_Click(object sender, EventArgs e)
        {
            if (dataGridViewSend.SelectedRows.Count > 0)
            {
                string remoteIp = txtRemoteIpSend.Text.Trim();
                string key = txtKeySend.Text.Trim();
                if (string.IsNullOrEmpty(remoteIp))
                {
                    MessageBox.Show("Vui lòng nhập địa chỉ IP của máy đích!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                int id = Convert.ToInt32(dataGridViewSend.SelectedRows[0].Cells["id"].Value);
                SendDataWithEncryption(id, remoteIp, key);
            }
            else
            {
                MessageBox.Show("Vui lòng chọn một dòng để gửi dữ liệu.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void SendDataWithEncryption(int id, string remoteIp, string key)
        {
            try
            {
                connection.Open();
                string query = "SELECT * FROM sensitive_data WHERE id = @id";
                DataTable dataTable = new DataTable();

                using (MySqlCommand cmd = new MySqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@id", id);
                    MySqlDataAdapter adapter = new MySqlDataAdapter(cmd);
                    adapter.Fill(dataTable);
                }

                if (dataTable.Rows.Count > 0)
                {
                    DataRow row = dataTable.Rows[0];
                    string maskedData = $"ID: {row["id"]}\n" +
                                       $"Full Name: {ApplyMaskingMethod(row["full_name"].ToString(), "name")}\n" +
                                       $"Email: {ApplyMaskingMethod(row["email"].ToString(), "email")}\n" +
                                       $"Phone: {ApplyMaskingMethod(row["phone"].ToString(), "phone")}\n" +
                                       $"Credit Card: {ApplyMaskingMethod(row["credit_card"].ToString(), "credit_card")}\n" +
                                       $"SSN: {ApplyMaskingMethod(row["ssn"].ToString(), "ssn")}\n" +
                                       $"Address: {ApplyMaskingMethod(row["address"].ToString(), "address")}\n" +
                                       $"Created At: {row["created_at"]}";

                    string originalData = $"ID: {row["id"]}\n" +
                                         $"Full Name: {row["full_name"]}\n" +
                                         $"Email: {row["email"]}\n" +
                                         $"Phone: {row["phone"]}\n" +
                                         $"Credit Card: {row["credit_card"]}\n" +
                                         $"SSN: {row["ssn"]}\n" +
                                         $"Address: {row["address"]}\n" +
                                         $"Created At: {row["created_at"]}";

                    string encryptedData = EncryptionHelper.Encrypt(originalData, key);

                    string jsonData = $"{{\"masked\": \"{maskedData.Replace("\n", "\\n")}\", \"encrypted\": \"{encryptedData}\"}}";

                    // Hiển thị JSON trong MessageBox trước khi gửi
                    MessageBox.Show($"Dữ liệu JSON sẽ được gửi:\n{jsonData}", "Xem JSON", MessageBoxButtons.OK, MessageBoxIcon.Information);

                    TcpClient client = new TcpClient(remoteIp, 8888);
                    NetworkStream stream = client.GetStream();
                    byte[] data = Encoding.UTF8.GetBytes(jsonData);
                    stream.Write(data, 0, data.Length);

                    MessageBox.Show($"Dữ liệu đã được gửi tới {remoteIp}!", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);

                    stream.Close();
                    client.Close();
                }
                connection.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi khi gửi dữ liệu: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);
            isServerRunning = false;
            server?.Stop();
        }
    }

    // Lớp mã hóa/giải mã AES
    public static class EncryptionHelper
    {
        private static readonly byte[] Sbox = new byte[] {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

        private static readonly byte[] Rcon = new byte[] {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

        private static byte[] KeyExpansion(byte[] key)
        {
            byte[] expandedKey = new byte[176]; // 44 words * 4 bytes = 176 bytes for AES-128
            Array.Copy(key, 0, expandedKey, 0, 16);
            int bytesGenerated = 16;
            int rconIteration = 0;

            while (bytesGenerated < 176)
            {
                byte[] temp = new byte[4];
                Array.Copy(expandedKey, bytesGenerated - 4, temp, 0, 4);

                if (bytesGenerated % 16 == 0)
                {
                    temp = SubWord(RotWord(temp));
                    temp[0] ^= Rcon[rconIteration++];
                }

                for (int i = 0; i < 4; i++)
                {
                    expandedKey[bytesGenerated] = (byte)(expandedKey[bytesGenerated - 16] ^ temp[i]);
                    bytesGenerated++;
                }
            }
            return expandedKey;
        }

        private static byte[] SubWord(byte[] word)
        {
            for (int i = 0; i < 4; i++)
                word[i] = Sbox[word[i]];
            return word;
        }

        private static byte[] RotWord(byte[] word)
        {
            byte temp = word[0];
            for (int i = 0; i < 3; i++)
                word[i] = word[i + 1];
            word[3] = temp;
            return word;
        }

        public static string Encrypt(string plainText, string key = null)
        {
            if (string.IsNullOrEmpty(plainText)) return plainText;
            key ??= "MySecretKey12345";

            byte[] keyBytes = Encoding.UTF8.GetBytes(key.PadRight(16, ' ').Substring(0, 16));
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] expandedKey = KeyExpansion(keyBytes);

            // Padding để đảm bảo độ dài là bội của 16
            int paddingLength = 16 - (plainBytes.Length % 16);
            Array.Resize(ref plainBytes, plainBytes.Length + paddingLength);
            for (int i = plainBytes.Length - paddingLength; i < plainBytes.Length; i++)
                plainBytes[i] = (byte)paddingLength;

            byte[] cipherBytes = new byte[plainBytes.Length];
            for (int i = 0; i < plainBytes.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(plainBytes, i, block, 0, 16);
                block = EncryptBlock(block, expandedKey);
                Array.Copy(block, 0, cipherBytes, i, 16);
            }

            return Convert.ToBase64String(cipherBytes);
        }

        public static string Decrypt(string cipherText, string key = null)
        {
            if (string.IsNullOrEmpty(cipherText)) return cipherText;
            key ??= "MySecretKey12345";

            byte[] keyBytes = Encoding.UTF8.GetBytes(key.PadRight(16, ' ').Substring(0, 16));
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] expandedKey = KeyExpansion(keyBytes);

            byte[] plainBytes = new byte[cipherBytes.Length];
            for (int i = 0; i < cipherBytes.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(cipherBytes, i, block, 0, 16);
                block = DecryptBlock(block, expandedKey);
                Array.Copy(block, 0, plainBytes, i, 16);
            }

            // Xóa padding
            int paddingLength = plainBytes[plainBytes.Length - 1];
            Array.Resize(ref plainBytes, plainBytes.Length - paddingLength);

            return Encoding.UTF8.GetString(plainBytes);
        }

        private static byte[] EncryptBlock(byte[] block, byte[] expandedKey)
        {
            byte[,] state = BytesToState(block);
            AddRoundKey(state, expandedKey, 0);

            for (int round = 1; round < 10; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, expandedKey, round * 4);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, expandedKey, 40);

            return StateToBytes(state);
        }

        private static byte[] DecryptBlock(byte[] block, byte[] expandedKey)
        {
            byte[,] state = BytesToState(block);
            AddRoundKey(state, expandedKey, 40);

            for (int round = 9; round > 0; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, expandedKey, round * 4);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, expandedKey, 0);

            return StateToBytes(state);
        }

        private static byte[,] BytesToState(byte[] input)
        {
            byte[,] state = new byte[4, 4];
            for (int i = 0; i < 16; i++)
                state[i % 4, i / 4] = input[i];
            return state;
        }

        private static byte[] StateToBytes(byte[,] state)
        {
            byte[] output = new byte[16];
            for (int i = 0; i < 16; i++)
                output[i] = state[i % 4, i / 4];
            return output;
        }

        private static void SubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = Sbox[state[i, j]];
        }

        private static void InvSubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = InvSbox[state[i, j]];
        }

        private static void ShiftRows(byte[,] state)
        {
            byte[] temp = new byte[4];
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    temp[j] = state[i, (j + i) % 4];
                for (int j = 0; j < 4; j++)
                    state[i, j] = temp[j];
            }
        }

        private static void InvShiftRows(byte[,] state)
        {
            byte[] temp = new byte[4];
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    temp[j] = state[i, (j - i + 4) % 4];
                for (int j = 0; j < 4; j++)
                    state[i, j] = temp[j];
            }
        }

        private static void MixColumns(byte[,] state)
        {
            for (int c = 0; c < 4; c++)
            {
                byte[] col = new byte[4];
                for (int i = 0; i < 4; i++)
                    col[i] = state[i, c];

                state[0, c] = (byte)(Gmul(2, col[0]) ^ Gmul(3, col[1]) ^ col[2] ^ col[3]);
                state[1, c] = (byte)(col[0] ^ Gmul(2, col[1]) ^ Gmul(3, col[2]) ^ col[3]);
                state[2, c] = (byte)(col[0] ^ col[1] ^ Gmul(2, col[2]) ^ Gmul(3, col[3]));
                state[3, c] = (byte)(Gmul(3, col[0]) ^ col[1] ^ col[2] ^ Gmul(2, col[3]));
            }
        }

        private static void InvMixColumns(byte[,] state)
        {
            for (int c = 0; c < 4; c++)
            {
                byte[] col = new byte[4];
                for (int i = 0; i < 4; i++)
                    col[i] = state[i, c];

                state[0, c] = (byte)(Gmul(0x0e, col[0]) ^ Gmul(0x0b, col[1]) ^ Gmul(0x0d, col[2]) ^ Gmul(0x09, col[3]));
                state[1, c] = (byte)(Gmul(0x09, col[0]) ^ Gmul(0x0e, col[1]) ^ Gmul(0x0b, col[2]) ^ Gmul(0x0d, col[3]));
                state[2, c] = (byte)(Gmul(0x0d, col[0]) ^ Gmul(0x09, col[1]) ^ Gmul(0x0e, col[2]) ^ Gmul(0x0b, col[3]));
                state[3, c] = (byte)(Gmul(0x0b, col[0]) ^ Gmul(0x0d, col[1]) ^ Gmul(0x09, col[2]) ^ Gmul(0x0e, col[3]));
            }
        }

        private static byte Gmul(byte a, byte b)
        {
            byte p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                    p ^= a;
                bool hiBitSet = (a & 0x80) != 0;
                a <<= 1;
                if (hiBitSet)
                    a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
                b >>= 1;
            }
            return p;
        }

        private static void AddRoundKey(byte[,] state, byte[] key, int offset)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] ^= key[offset + i + 4 * j];
        }

        private static readonly byte[] InvSbox = new byte[] {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    }

    // Form thêm dữ liệu mới (giữ nguyên)
    public class AddDataForm : Form
    {
        private MySqlConnection connection;
        private TextBox txtName, txtEmail, txtPhone, txtCreditCard, txtSSN, txtAddress;
        private Button btnSave, btnCancel;

        public AddDataForm(MySqlConnection conn)
        {
            connection = conn;
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            this.Text = "Thêm Dữ Liệu Mới";
            this.Size = new Size(400, 350);
            this.StartPosition = FormStartPosition.CenterParent;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;

            Label lblName = new Label { Text = "Họ tên:", Location = new Point(20, 20), Size = new Size(100, 20) };
            txtName = new TextBox { Location = new Point(130, 20), Size = new Size(220, 20) };

            Label lblEmail = new Label { Text = "Email:", Location = new Point(20, 50), Size = new Size(100, 20) };
            txtEmail = new TextBox { Location = new Point(130, 50), Size = new Size(220, 20) };

            Label lblPhone = new Label { Text = "Số điện thoại:", Location = new Point(20, 80), Size = new Size(100, 20) };
            txtPhone = new TextBox { Location = new Point(130, 80), Size = new Size(220, 20) };

            Label lblCreditCard = new Label { Text = "Thẻ tín dụng:", Location = new Point(20, 110), Size = new Size(100, 20) };
            txtCreditCard = new TextBox { Location = new Point(130, 110), Size = new Size(220, 20) };

            Label lblSSN = new Label { Text = "Số SSN:", Location = new Point(20, 140), Size = new Size(100, 20) };
            txtSSN = new TextBox { Location = new Point(130, 140), Size = new Size(220, 20) };

            Label lblAddress = new Label { Text = "Địa chỉ:", Location = new Point(20, 170), Size = new Size(100, 20) };
            txtAddress = new TextBox { Location = new Point(130, 170), Size = new Size(220, 60), Multiline = true };

            btnSave = new Button { Text = "Lưu", Location = new Point(130, 250), Size = new Size(100, 30) };
            btnSave.Click += new EventHandler(btnSave_Click);

            btnCancel = new Button { Text = "Hủy", Location = new Point(250, 250), Size = new Size(100, 30) };
            btnCancel.Click += new EventHandler(btnCancel_Click);

            this.Controls.AddRange(new Control[] { lblName, txtName, lblEmail, txtEmail, lblPhone, txtPhone, lblCreditCard, txtCreditCard, lblSSN, txtSSN, lblAddress, txtAddress, btnSave, btnCancel });
        }

        private void btnSave_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(txtName.Text) || string.IsNullOrWhiteSpace(txtEmail.Text))
                {
                    MessageBox.Show("Vui lòng nhập ít nhất Họ tên và Email", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                if (connection.State != ConnectionState.Open)
                    connection.Open();

                string query = @"INSERT INTO sensitive_data 
                                (full_name, email, phone, credit_card, ssn, address) 
                                VALUES 
                                (@name, @email, @phone, @creditCard, @ssn, @address)";

                using (MySqlCommand cmd = new MySqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@name", txtName.Text);
                    cmd.Parameters.AddWithValue("@email", txtEmail.Text);
                    cmd.Parameters.AddWithValue("@phone", txtPhone.Text);
                    cmd.Parameters.AddWithValue("@creditCard", txtCreditCard.Text);
                    cmd.Parameters.AddWithValue("@ssn", txtSSN.Text);
                    cmd.Parameters.AddWithValue("@address", txtAddress.Text);
                    cmd.ExecuteNonQuery();
                }

                connection.Close();
                this.DialogResult = DialogResult.OK;
                this.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi thêm dữ liệu: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }
    }

    // Form xem dữ liệu gốc (giữ nguyên)
    public class ViewOriginalDataForm : Form
    {
        private MySqlConnection connection;
        private int dataId;
        private TextBox txtPassword;
        private Button btnAuthenticate;
        private Panel pnlData;

        public ViewOriginalDataForm(MySqlConnection conn, int id)
        {
            connection = conn;
            dataId = id;
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            this.Text = "Xem Dữ Liệu Gốc";
            this.Size = new Size(450, 400);
            this.StartPosition = FormStartPosition.CenterParent;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;

            Panel pnlAuth = new Panel { Size = new Size(430, 80), Location = new Point(10, 10), BorderStyle = BorderStyle.FixedSingle };
            Label lblPassword = new Label { Text = "Nhập mật khẩu để xem dữ liệu gốc:", Location = new Point(10, 15), Size = new Size(200, 20) };
            txtPassword = new TextBox { Location = new Point(10, 40), Size = new Size(300, 20), PasswordChar = '*' };
            btnAuthenticate = new Button { Text = "Xác thực", Location = new Point(320, 39), Size = new Size(90, 22) };
            btnAuthenticate.Click += new EventHandler(btnAuthenticate_Click);
            pnlAuth.Controls.AddRange(new Control[] { lblPassword, txtPassword, btnAuthenticate });

            pnlData = new Panel { Size = new Size(430, 260), Location = new Point(10, 100), BorderStyle = BorderStyle.FixedSingle, Visible = false };

            this.Controls.AddRange(new Control[] { pnlAuth, pnlData });
        }

        private void btnAuthenticate_Click(object sender, EventArgs e)
        {
            if (txtPassword.Text == "admin123")
            {
                ShowOriginalData();
            }
            else
            {
                MessageBox.Show("Mật khẩu không đúng!", "Lỗi xác thực", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ShowOriginalData()
        {
            try
            {
                if (connection.State != ConnectionState.Open)
                    connection.Open();

                string query = "SELECT * FROM sensitive_data WHERE id = @id";
                using (MySqlCommand cmd = new MySqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@id", dataId);
                    using (MySqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            pnlData.Controls.Clear();
                            Label lblTitle = new Label { Text = "Dữ liệu gốc:", Font = new Font("Microsoft Sans Serif", 10, FontStyle.Bold), Location = new Point(10, 10), Size = new Size(400, 20) };
                            pnlData.Controls.Add(lblTitle);

                            int yPos = 40;
                            AddDataLabel("ID:", reader["id"].ToString(), yPos); yPos += 30;
                            AddDataLabel("Họ tên:", reader["full_name"].ToString(), yPos); yPos += 30;
                            AddDataLabel("Email:", reader["email"].ToString(), yPos); yPos += 30;
                            AddDataLabel("Số điện thoại:", reader["phone"].ToString(), yPos); yPos += 30;
                            AddDataLabel("Thẻ tín dụng:", reader["credit_card"].ToString(), yPos); yPos += 30;
                            AddDataLabel("SSN:", reader["ssn"].ToString(), yPos); yPos += 30;
                            AddDataLabel("Địa chỉ:", reader["address"].ToString(), yPos);

                            pnlData.Visible = true;
                        }
                        else
                        {
                            MessageBox.Show("Không tìm thấy dữ liệu!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                    }
                }
                connection.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi hiển thị dữ liệu: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }

        private void AddDataLabel(string labelText, string value, int yPosition)
        {
            Label lbl = new Label { Text = labelText, Location = new Point(10, yPosition), Size = new Size(100, 20), Font = new Font("Microsoft Sans Serif", 9, FontStyle.Bold) };
            TextBox txt = new TextBox { Text = value, Location = new Point(120, yPosition), Size = new Size(280, 20), ReadOnly = true };
            pnlData.Controls.AddRange(new Control[] { lbl, txt });
        }
    }

    // Form chọn phương thức che mặt nạ (giữ nguyên)
    public class MaskingMethodForm : Form
    {
        private ComboBox cmbMaskingMethod;
        private Button btnApply, btnCancel;

        public MaskingMethodForm()
        {
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            this.Text = "Chọn Phương Thức Che Mặt Nạ";
            this.Size = new Size(350, 150);
            this.StartPosition = FormStartPosition.CenterParent;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;

            Label lblMethod = new Label { Text = "Chọn phương thức:", Location = new Point(20, 20), Size = new Size(120, 20) };
            cmbMaskingMethod = new ComboBox { Location = new Point(150, 20), Size = new Size(160, 20), DropDownStyle = ComboBoxStyle.DropDownList };
            cmbMaskingMethod.Items.AddRange(new object[] { "Che mặt nạ ký tự", "Xáo trộn dữ liệu", "Thay thế bằng dữ liệu giả", "Thêm nhiễu vào dữ liệu số" });
            cmbMaskingMethod.SelectedIndex = Properties.Settings.Default.MaskingMethod;

            btnApply = new Button { Text = "Áp dụng", Location = new Point(150, 60), Size = new Size(80, 30) };
            btnApply.Click += new EventHandler(btnApply_Click);

            btnCancel = new Button { Text = "Hủy", Location = new Point(240, 60), Size = new Size(70, 30) };
            btnCancel.Click += new EventHandler(btnCancel_Click);

            this.Controls.AddRange(new Control[] { lblMethod, cmbMaskingMethod, btnApply, btnCancel });
        }

        private void btnApply_Click(object sender, EventArgs e)
        {
            Properties.Settings.Default.MaskingMethod = cmbMaskingMethod.SelectedIndex;
            Properties.Settings.Default.Save();
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }
    }

    // Thiết kế giao diện chính với 3 tab
    partial class MainForm
    {
        private DataGridView dataGridViewReceive;
        private System.ComponentModel.IContainer components = null;
        private TabControl tabControl;
        private TabPage tabManage, tabSend, tabReceive;
        private DataGridView dataGridViewManage, dataGridViewSend;
        private Button btnAddData, btnViewOriginal, btnChangeMaskingMethod, btnSendData;
        private Label label1, lblKeySend, lblRemoteIpSend, lblKeyReceive, lblReceivedData;
        private TextBox txtKeySend, txtRemoteIpSend, txtKeyReceive, txtReceivedData;
        private StatusStrip statusStrip;
        private ToolStripStatusLabel statusLabel;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.tabControl = new TabControl();
            this.tabManage = new TabPage();
            this.tabSend = new TabPage();
            this.tabReceive = new TabPage();
            this.dataGridViewManage = new DataGridView();
            this.dataGridViewSend = new DataGridView();
            this.btnAddData = new Button();
            this.btnViewOriginal = new Button();
            this.btnChangeMaskingMethod = new Button();
            this.btnSendData = new Button();
            this.label1 = new Label();
            this.lblKeySend = new Label();
            this.lblRemoteIpSend = new Label();
            this.txtKeySend = new TextBox();
            this.txtRemoteIpSend = new TextBox();
            this.lblKeyReceive = new Label();
            this.lblReceivedData = new Label();
            this.txtKeyReceive = new TextBox();
            this.txtReceivedData = new TextBox();
            this.statusStrip = new StatusStrip();
            this.statusLabel = new ToolStripStatusLabel();

            // TabControl
            tabControl.Location = new Point(12, 12);
            tabControl.Size = new Size(760, 450);
            tabControl.TabPages.AddRange(new TabPage[] { tabManage, tabSend, tabReceive });

            // Tab Quản lý dữ liệu
            tabManage.Text = "Quản lý Dữ liệu";
            dataGridViewManage.Location = new Point(12, 50);
            dataGridViewManage.Size = new Size(730, 300);
            dataGridViewManage.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            dataGridViewManage.ReadOnly = true;
            dataGridViewManage.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            label1.Text = "Quản Lý Dữ Liệu An Toàn - Mặt Nạ Dữ Liệu";
            label1.Font = new Font("Microsoft Sans Serif", 12F, FontStyle.Bold);
            label1.Location = new Point(12, 20);
            btnAddData.Text = "Thêm Dữ Liệu Mới";
            btnAddData.Location = new Point(12, 360);
            btnAddData.Size = new Size(120, 30);
            btnAddData.Click += new EventHandler(btnAddData_Click);
            btnViewOriginal.Text = "Xem Dữ Liệu Gốc";
            btnViewOriginal.Location = new Point(138, 360);
            btnViewOriginal.Size = new Size(120, 30);
            btnViewOriginal.Click += new EventHandler(btnViewOriginal_Click);
            btnChangeMaskingMethod.Text = "Đổi Phương Thức Che Mặt Nạ";
            btnChangeMaskingMethod.Location = new Point(612, 360);
            btnChangeMaskingMethod.Size = new Size(130, 30);
            btnChangeMaskingMethod.Click += new EventHandler(btnChangeMaskingMethod_Click);
            tabManage.Controls.AddRange(new Control[] { dataGridViewManage, label1, btnAddData, btnViewOriginal, btnChangeMaskingMethod });

            // Tab Gửi dữ liệu
            tabSend.Text = "Gửi Dữ liệu";
            dataGridViewSend.Location = new Point(12, 20);
            dataGridViewSend.Size = new Size(730, 250);
            dataGridViewSend.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            dataGridViewSend.ReadOnly = true;
            dataGridViewSend.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            lblKeySend.Text = "Key mã hóa:";
            lblKeySend.Location = new Point(12, 280);
            lblKeySend.Size = new Size(100, 20);
            txtKeySend.Location = new Point(120, 280);
            txtKeySend.Size = new Size(200, 20);
            lblRemoteIpSend.Text = "IP đích:";
            lblRemoteIpSend.Location = new Point(12, 310);
            lblRemoteIpSend.Size = new Size(100, 20);
            txtRemoteIpSend.Location = new Point(120, 310);
            txtRemoteIpSend.Size = new Size(200, 20);
            btnSendData.Text = "Gửi Dữ liệu";
            btnSendData.Location = new Point(120, 340);
            btnSendData.Size = new Size(100, 30);
            btnSendData.Click += new EventHandler(btnSendData_Click);
            tabSend.Controls.AddRange(new Control[] { dataGridViewSend, lblKeySend, txtKeySend, lblRemoteIpSend, txtRemoteIpSend, btnSendData });

            // Tab Nhận dữ liệu
            tabReceive.Text = "Nhận Dữ liệu";
            lblKeyReceive.Text = "Key giải mã:";
            lblKeyReceive.Location = new Point(12, 20);
            lblKeyReceive.Size = new Size(100, 20);
            txtKeyReceive.Location = new Point(120, 20);
            txtKeyReceive.Size = new Size(200, 20);
            lblReceivedData.Text = "Dữ liệu nhận được:";
            lblReceivedData.Location = new Point(12, 50);
            lblReceivedData.Size = new Size(100, 20);

            // Thay txtReceivedData bằng dataGridViewReceive
            dataGridViewReceive = new DataGridView();
            dataGridViewReceive.Location = new Point(12, 80);
            dataGridViewReceive.Size = new Size(730, 320);
            dataGridViewReceive.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            dataGridViewReceive.ReadOnly = true;
            dataGridViewReceive.SelectionMode = DataGridViewSelectionMode.FullRowSelect;

            tabReceive.Controls.AddRange(new Control[] { lblKeyReceive, txtKeyReceive, lblReceivedData, dataGridViewReceive });

            // StatusStrip
            statusStrip.Items.Add(statusLabel);
            statusStrip.Location = new Point(0, 469);
            statusStrip.Size = new Size(784, 22);
            statusLabel.Text = "Sẵn sàng";

            // MainForm
            this.AutoScaleDimensions = new SizeF(6F, 13F);
            this.AutoScaleMode = AutoScaleMode.Font;
            this.ClientSize = new Size(784, 491);
            this.Controls.Add(this.statusStrip);
            this.Controls.Add(this.tabControl);
            this.MinimumSize = new Size(800, 530);
            this.Name = "MainForm";
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Text = "Quản Lý Dữ Liệu An Toàn và Truyền Dữ Liệu";
            ((System.ComponentModel.ISupportInitialize)(this.dataGridViewManage)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridViewSend)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridViewReceive)).BeginInit(); // Thêm cho DataGridView mới
            ((System.ComponentModel.ISupportInitialize)(this.dataGridViewReceive)).EndInit();   // Thêm cho DataGridView mới
            this.statusStrip.ResumeLayout(false);
            this.statusStrip.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();
        }
    }

    // Lớp chương trình chính (giữ nguyên)
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    // Cài đặt (giữ nguyên)
    namespace Properties
    {
        internal sealed class Settings : ApplicationSettingsBase
        {
            private static Settings defaultInstance = ((Settings)(ApplicationSettingsBase.Synchronized(new Settings())));

            public static Settings Default
            {
                get { return defaultInstance; }
            }

            [UserScopedSetting()]
            [DefaultSettingValue("0")]
            public int MaskingMethod
            {
                get { return ((int)(this["MaskingMethod"])); }
                set { this["MaskingMethod"] = value; }
            }
        }
    }
}