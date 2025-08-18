# FTP Server

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![C Standard](https://img.shields.io/badge/C-C99-blue.svg)]()

A robust, secure FTP server implementation written in C with SSL/TLS support and comprehensive logging capabilities.

## 🚀 Features

- **Secure Communication**: Full SSL/TLS encryption support for secure file transfers
- **Configurable Architecture**: Flexible configuration system with customizable parameters
- **Concurrent Connections**: Multi-client support with configurable connection limits
- **Comprehensive Logging**: Detailed server event logging for monitoring and debugging
- **Cross-Platform**: Compatible with Linux and Unix-like systems
- **Performance Optimized**: Efficient buffer management and connection handling

## 📋 Prerequisites

Before building and running the FTP server, ensure you have the following dependencies installed:

### System Requirements
- **Operating System**: Linux/Unix-like system
- **Compiler**: GCC 4.9+ or Clang 3.5+
- **Build System**: CMake 3.10+

### Dependencies
- **OpenSSL**: Required for SSL/TLS encryption
  ```bash
  # Ubuntu/Debian
  sudo apt-get install libssl-dev
  
  # CentOS/RHEL
  sudo yum install openssl-devel
  
  # macOS
  brew install openssl
  ```

## 🔧 Building the Server

This project uses CMake for cross-platform building. Follow these steps:

### Quick Build
```bash
# Clone and build in one go
git clone <repository-url>
cd ftp-server
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Step-by-Step Build Process

1. **Create build directory:**
   ```bash
   mkdir build && cd build
   ```

2. **Configure with CMake:**
   ```bash
   # Release build (optimized, default)
   cmake -DCMAKE_BUILD_TYPE=Release ..
   
   # Debug build (with debug symbols)
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   ```

3. **Build options:**
   ```bash
   # Build with tests (default)
   cmake -DBUILD_TESTING=ON ..
   
   # Build without tests
   cmake -DBUILD_TESTING=OFF ..
   ```

4. **Compile the project:**
   ```bash
   make -j$(nproc)  # Use all available CPU cores
   ```

5. **Verify build:**
   ```bash
   ls -la my_ftp_server  # Should show the executable
   ```

The executable `my_ftp_server` will be created in the `build` directory.

### Build Types

- **Release** (`-DCMAKE_BUILD_TYPE=Release`): Optimized build with `-O3` optimization
- **Debug** (`-DCMAKE_BUILD_TYPE=Debug`): Debug build with symbols and no optimization

## ⚙️ Configuration

The server uses a configuration file (`server.conf`) for customization. Create this file in your working directory before running the server.

### Configuration Parameters

| Parameter | Description | Default Value | Valid Range |
|-----------|-------------|---------------|-------------|
| `port` | Server listening port | `21` | 1-65535 |
| `max_clients` | Maximum concurrent connections | `10` | 1-1000 |
| `buffer_size` | I/O buffer size (bytes) | `8192` | 1024-65536 |
| `ftp_root` | FTP root directory path | `/tmp/myftp_root` | Valid directory path |
| `cert_file` | SSL certificate file path | `/etc/ssl/certs/myftp.crt` | Valid file path |
| `key_file` | SSL private key file path | `/etc/ssl/private/myftp.key` | Valid file path |
| `client_timeout` | Control connection timeout (seconds) | `300` | 30-3600 |
| `data_timeout` | Data connection timeout (seconds) | `60` | 10-600 |

### Sample Configuration File

Create a `server.conf` file with your desired settings:

```ini
# FTP Server Configuration
port=2121
max_clients=20
buffer_size=16384
ftp_root=/home/ftp/data
cert_file=/etc/ssl/certs/ftp-server.crt
key_file=/etc/ssl/private/ftp-server.key
client_timeout=600
data_timeout=120
```

## 🚀 Running the Server

### Basic Usage

1. **Ensure configuration file exists:**
   ```bash
   ls server.conf  # Should exist in current directory
   ```

2. **Start the server:**
   ```bash
   ./build/my_ftp_server
   ```

3. **Verify server is running:**
   ```bash
   netstat -tlnp | grep :21  # Check if port 21 is listening
   ```

### Advanced Usage

#### Running with Custom Configuration
```bash
# Specify custom config file location
./build/my_ftp_server --config /path/to/custom.conf
```


#### Monitoring Server Logs
```bash
# Follow log output in real-time
tail -f ftp-server.log
```

## 🧪 Testing

### Unit Tests

The project includes comprehensive unit tests that are built by default.

```bash
# Build and run tests
cd build
make -j$(nproc)
make test

# Run tests with verbose output
ctest --verbose

# Run specific test
ctest -R ParserTest
```

### Disabling Tests

If you don't need tests (e.g., for production builds):

```bash
cmake -DBUILD_TESTING=OFF ..
make -j$(nproc)
```

### Manual Testing
```bash
# Test connection with FTP client
ftp localhost 21

# Test with secure FTP client
sftp -P 21 localhost
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Troubleshooting

### Common Issues

**Server won't start:**
- Check if port is already in use: `netstat -tlnp | grep :21`
- Verify configuration file syntax
- Ensure SSL certificates exist and are readable

**SSL/TLS errors:**
- Verify certificate and key file paths
- Check certificate validity: `openssl x509 -in cert.pem -text -noout`
- Ensure proper file permissions

**Connection timeouts:**
- Adjust `client_timeout` and `data_timeout` values
- Check firewall settings
- Verify network connectivity

### Getting Help

- Check the [Issues](../../issues) page for known problems
- Review server logs for detailed error messages
- Ensure all dependencies are properly installed

## 📊 Performance Notes

- Default buffer size (8192 bytes) is optimized for most use cases
- Increase `max_clients` based on your system's capacity
- Monitor system resources when handling many concurrent connections
- Consider using a reverse proxy for production deployments
