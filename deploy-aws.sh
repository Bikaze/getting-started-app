#!/bin/bash

# Exit on error
set -e

# AWS CLI Configuration Prerequisites:
# 1. AWS CLI installed (aws --version)
# 2. AWS CLI configured with proper credentials (aws configure)
# 3. Key pair for EC2 access already created in your AWS account
# 4. Appropriate IAM permissions to create resources

# Variables - modify these as needed
VPC_CIDR="10.0.0.0/16"
PUBLIC_SUBNET_CIDR="10.0.1.0/24"
PRIVATE_SUBNET_CIDR="10.0.2.0/24"
AVAILABILITY_ZONE="eu-west-1a"
KEY_NAME="" # Replace with your key pair name
INSTANCE_TYPE="t2.micro"     # Increased for better performance
AMI_ID="ami-0df368112825f8d8f" # Ubuntu 22.04 LTS - update for your region

echo "Creating VPC infrastructure for Node.js app with MySQL database..."

echo "Creating VPC..."
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block $VPC_CIDR \
  --query 'Vpc.VpcId' \
  --output text)
aws ec2 create-tags --resources $VPC_ID --tags Key=Name,Value=AppVPC

# Enable DNS support and hostnames for the VPC
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames

echo "Creating Internet Gateway..."
IGW_ID=$(aws ec2 create-internet-gateway \
  --query 'InternetGateway.InternetGatewayId' \
  --output text)
aws ec2 create-tags --resources $IGW_ID --tags Key=Name,Value=AppIGW

echo "Attaching Internet Gateway to VPC..."
aws ec2 attach-internet-gateway \
  --internet-gateway-id $IGW_ID \
  --vpc-id $VPC_ID

echo "Creating Public Subnet for Node.js App..."
PUBLIC_SUBNET_ID=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block $PUBLIC_SUBNET_CIDR \
  --availability-zone $AVAILABILITY_ZONE \
  --query 'Subnet.SubnetId' \
  --output text)
aws ec2 create-tags --resources $PUBLIC_SUBNET_ID --tags Key=Name,Value=PublicAppSubnet

echo "Creating Private Subnet for MySQL Database..."
PRIVATE_SUBNET_ID=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block $PRIVATE_SUBNET_CIDR \
  --availability-zone $AVAILABILITY_ZONE \
  --query 'Subnet.SubnetId' \
  --output text)
aws ec2 create-tags --resources $PRIVATE_SUBNET_ID --tags Key=Name,Value=PrivateDBSubnet

echo "Creating Public Route Table..."
PUBLIC_RT_ID=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --query 'RouteTable.RouteTableId' \
  --output text)
aws ec2 create-tags --resources $PUBLIC_RT_ID --tags Key=Name,Value=PublicRT

echo "Creating route to Internet Gateway..."
aws ec2 create-route \
  --route-table-id $PUBLIC_RT_ID \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $IGW_ID

echo "Associating Public Subnet with Public Route Table..."
PUBLIC_SUBNET_RT_ASSOC=$(aws ec2 associate-route-table \
  --route-table-id $PUBLIC_RT_ID \
  --subnet-id $PUBLIC_SUBNET_ID \
  --query 'AssociationId' \
  --output text)

echo "Creating Private Route Table..."
PRIVATE_RT_ID=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --query 'RouteTable.RouteTableId' \
  --output text)
aws ec2 create-tags --resources $PRIVATE_RT_ID --tags Key=Name,Value=PrivateRT

echo "Associating Private Subnet with Private Route Table..."
PRIVATE_SUBNET_RT_ASSOC=$(aws ec2 associate-route-table \
  --route-table-id $PRIVATE_RT_ID \
  --subnet-id $PRIVATE_SUBNET_ID \
  --query 'AssociationId' \
  --output text)

# Create NAT Gateway for private subnet internet access
echo "Creating Elastic IP for NAT Gateway..."
EIP_ALLOC_ID=$(aws ec2 allocate-address \
  --domain vpc \
  --query 'AllocationId' \
  --output text)

echo "Creating NAT Gateway..."
NAT_GW_ID=$(aws ec2 create-nat-gateway \
  --subnet-id $PUBLIC_SUBNET_ID \
  --allocation-id $EIP_ALLOC_ID \
  --query 'NatGateway.NatGatewayId' \
  --output text)
aws ec2 create-tags --resources $NAT_GW_ID --tags Key=Name,Value=AppNATGateway

echo "Waiting for NAT Gateway to become available..."
aws ec2 wait nat-gateway-available --nat-gateway-ids $NAT_GW_ID

echo "Creating route from Private subnet to NAT Gateway..."
aws ec2 create-route \
  --route-table-id $PRIVATE_RT_ID \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id $NAT_GW_ID

echo "Creating App Security Group..."
APP_SG_ID=$(aws ec2 create-security-group \
  --group-name AppSG \
  --description "Security group for Node.js application" \
  --vpc-id $VPC_ID \
  --query 'GroupId' \
  --output text)
aws ec2 create-tags --resources $APP_SG_ID --tags Key=Name,Value=AppSG

echo "Creating Database Security Group..."
DB_SG_ID=$(aws ec2 create-security-group \
  --group-name DBSG \
  --description "Security group for MySQL database" \
  --vpc-id $VPC_ID \
  --query 'GroupId' \
  --output text)
aws ec2 create-tags --resources $DB_SG_ID --tags Key=Name,Value=DBSG

echo "Configuring App Security Group rules..."
# Allow SSH from anywhere
aws ec2 authorize-security-group-ingress \
  --group-id $APP_SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Allow HTTP from anywhere
aws ec2 authorize-security-group-ingress \
  --group-id $APP_SG_ID \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0

# Allow Node.js app port from anywhere
aws ec2 authorize-security-group-ingress \
  --group-id $APP_SG_ID \
  --protocol tcp \
  --port 3000 \
  --cidr 0.0.0.0/0

# # Allow all outbound traffic
# aws ec2 authorize-security-group-egress \
#   --group-id $APP_SG_ID \
#   --protocol all \
#   --port all \
#   --cidr 0.0.0.0/0

echo "Configuring Database Security Group rules..."
# Allow MySQL access only from App security group
aws ec2 authorize-security-group-ingress \
  --group-id $DB_SG_ID \
  --protocol tcp \
  --port 3306 \
  --source-group $APP_SG_ID

# Allow SSH only from App security group for maintenance
aws ec2 authorize-security-group-ingress \
  --group-id $DB_SG_ID \
  --protocol tcp \
  --port 22 \
  --source-group $APP_SG_ID

# # Allow all outbound traffic for updates
# aws ec2 authorize-security-group-egress \
#   --group-id $DB_SG_ID \
#   --protocol all \
#   --port all \
#   --cidr 0.0.0.0/0

echo "Creating Network ACL for Public Subnet..."
PUBLIC_NACL_ID=$(aws ec2 create-network-acl \
  --vpc-id $VPC_ID \
  --query 'NetworkAcl.NetworkAclId' \
  --output text)
aws ec2 create-tags --resources $PUBLIC_NACL_ID --tags Key=Name,Value=PublicNACL

echo "Creating Network ACL for Private Subnet..."
PRIVATE_NACL_ID=$(aws ec2 create-network-acl \
  --vpc-id $VPC_ID \
  --query 'NetworkAcl.NetworkAclId' \
  --output text)
aws ec2 create-tags --resources $PRIVATE_NACL_ID --tags Key=Name,Value=PrivateNACL

# Configure Public NACL rules
echo "Configuring Public NACL rules..."
# Allow inbound HTTP, HTTPS, SSH, and ephemeral ports
aws ec2 create-network-acl-entry \
  --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 100 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block 0.0.0.0/0 \
  --port-range From=80,To=80

aws ec2 create-network-acl-entry \
  --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 110 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block 0.0.0.0/0 \
  --port-range From=443,To=443

aws ec2 create-network-acl-entry \
  --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 120 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block 0.0.0.0/0 \
  --port-range From=22,To=22

aws ec2 create-network-acl-entry \
  --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 130 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block 0.0.0.0/0 \
  --port-range From=3000,To=3000

aws ec2 create-network-acl-entry \
  --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 140 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block 0.0.0.0/0 \
  --port-range From=1024,To=65535

# Allow all outbound traffic
aws ec2 create-network-acl-entry \
  --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 100 \
  --protocol -1 \
  --rule-action allow \
  --egress \
  --cidr-block 0.0.0.0/0

# Configure Private NACL rules
echo "Configuring Private NACL rules..."
# Allow inbound MySQL from public subnet only
aws ec2 create-network-acl-entry \
  --network-acl-id $PRIVATE_NACL_ID \
  --rule-number 100 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block $PUBLIC_SUBNET_CIDR \
  --port-range From=3306,To=3306

# Allow inbound SSH from public subnet only
aws ec2 create-network-acl-entry \
  --network-acl-id $PRIVATE_NACL_ID \
  --rule-number 110 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block $PUBLIC_SUBNET_CIDR \
  --port-range From=22,To=22

# Allow inbound ephemeral ports for return traffic
aws ec2 create-network-acl-entry \
  --network-acl-id $PRIVATE_NACL_ID \
  --rule-number 120 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block 0.0.0.0/0 \
  --port-range From=1024,To=65535

# Allow all outbound traffic
aws ec2 create-network-acl-entry \
  --network-acl-id $PRIVATE_NACL_ID \
  --rule-number 100 \
  --protocol -1 \
  --rule-action allow \
  --egress \
  --cidr-block 0.0.0.0/0

# Associate NACLs with Subnets
echo "Associating NACLs with Subnets..."
PUBLIC_SUBNET_NACL_ASSOC=$(aws ec2 replace-network-acl-association \
  --association-id $(aws ec2 describe-network-acls --filters Name=vpc-id,Values=$VPC_ID Name=association.subnet-id,Values=$PUBLIC_SUBNET_ID --query 'NetworkAcls[0].Associations[0].NetworkAclAssociationId' --output text) \
  --network-acl-id $PUBLIC_NACL_ID \
  --query 'NewAssociationId' \
  --output text)

PRIVATE_SUBNET_NACL_ASSOC=$(aws ec2 replace-network-acl-association \
  --association-id $(aws ec2 describe-network-acls --filters Name=vpc-id,Values=$VPC_ID Name=association.subnet-id,Values=$PRIVATE_SUBNET_ID --query 'NetworkAcls[0].Associations[0].NetworkAclAssociationId' --output text) \
  --network-acl-id $PRIVATE_NACL_ID \
  --query 'NewAssociationId' \
  --output text)

# Enable auto-assign public IP for public subnet
echo "Enabling auto-assign public IP for public subnet..."
aws ec2 modify-subnet-attribute \
  --subnet-id $PUBLIC_SUBNET_ID \
  --map-public-ip-on-launch

# First launch the MySQL instance to get its private IP
echo "Launching MySQL instance in private subnet..."
# Fix the JavaScript code embedding in the PRIVATE_USER_DATA section
PRIVATE_USER_DATA=$(cat <<'EOF'
#!/bin/bash
# Install curl and netcat for health checks
apt-get update
apt-get install -y curl netcat

# Install Docker using official script
curl -o get-docker.sh https://get.docker.com/
bash get-docker.sh
# Start and enable Docker
systemctl start docker
systemctl enable docker
# Add default user to docker group
usermod -aG docker ubuntu

# Create a healthcheck script for MySQL
cat > /home/ubuntu/mysql-healthcheck.sh <<'HEALTHSCRIPT'
#!/bin/bash
# Check MySQL using docker exec
docker exec mysql mysqladmin ping -h localhost -u root -psecret > /dev/null 2>&1
STATUS=$?
if [ $STATUS -eq 0 ]; then
  echo "MySQL ready"
  exit 0
else
  echo "MySQL not ready"
  exit 1
fi
HEALTHSCRIPT

chmod +x /home/ubuntu/mysql-healthcheck.sh

# Run MySQL container with healthcheck
docker run -d \
  --name mysql \
  -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD="secret" \
  -e MYSQL_DATABASE="todos" \
  --health-cmd="mysqladmin ping -h localhost -u root -psecret" \
  --health-interval=10s \
  --health-timeout=5s \
  --health-retries=5 \
  mysql:8.0

# Save JavaScript to file instead of using heredoc
cat > /home/ubuntu/healthcheck-server.js <<'JSCODE'
const http = require('http');
const { exec } = require('child_process');
const fs = require('fs');

// Create a log file for debugging
const logFile = '/home/ubuntu/healthcheck-debug.log';

// Helper function to write to log file
function writeToLog(message) {
  const timestamp = new Date().toISOString();
  fs.appendFileSync(logFile, `${timestamp}: ${message}\n`);
}

writeToLog('Health check server starting...');

// Check Docker container status
function checkDockerStatus(callback) {
  exec('docker ps -a --filter "name=mysql" --format "{{.Status}}"', (error, stdout, stderr) => {
    if (error) {
      writeToLog(`Docker status check error: ${error}`);
      callback(`Docker command failed: ${error.message}`);
      return;
    }
    if (stderr) {
      writeToLog(`Docker stderr: ${stderr}`);
    }
    writeToLog(`Docker container status: ${stdout.trim()}`);
    callback(null, stdout.trim());
  });
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    writeToLog(`Health check requested from ${req.connection.remoteAddress}`);
    
    // First check Docker container status
    checkDockerStatus((dockerError, dockerStatus) => {
      // Then run the MySQL health check
      exec('/home/ubuntu/mysql-healthcheck.sh', (error, stdout, stderr) => {
        const response = {
          status: error ? 'error' : 'ok',
          message: error ? 'MySQL not ready' : 'MySQL ready',
          mysqlOutput: stdout ? stdout.trim() : null,
          mysqlError: stderr ? stderr.trim() : null,
          dockerStatus: dockerStatus || 'unknown',
          error: error ? error.message : null,
          timestamp: new Date().toISOString()
        };
        
        writeToLog(`Health check result: ${JSON.stringify(response)}`);
        
        if (error) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(response, null, 2));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(response, null, 2));
        }
      });
    });
  } else if (req.url === '/debug') {
    // Add a debug endpoint to see logs
    try {
      const logs = fs.readFileSync(logFile, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(logs);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(`Error reading logs: ${e.message}`);
    }
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  }
});

// Add error handling for the server
server.on('error', (e) => {
  writeToLog(`Server error: ${e.message}`);
});

server.listen(8080, () => {
  writeToLog('Health check server running on port 8080');
  console.log('Health check server running on port 8080');
});
JSCODE

# Install Node.js for the health check server
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Create log file with proper permissions
touch /home/ubuntu/healthcheck-debug.log
chmod 666 /home/ubuntu/healthcheck-debug.log
touch /home/ubuntu/healthcheck-server.log
chmod 666 /home/ubuntu/healthcheck-server.log

# Start the health check server
node /home/ubuntu/healthcheck-server.js > /home/ubuntu/healthcheck-server.log 2>&1 &

echo "MySQL and health check server setup complete"
EOF
)

PRIVATE_INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_NAME \
  --subnet-id $PRIVATE_SUBNET_ID \
  --security-group-ids $DB_SG_ID \
  --user-data "$PRIVATE_USER_DATA" \
  --query 'Instances[0].InstanceId' \
  --output text)
aws ec2 create-tags --resources $PRIVATE_INSTANCE_ID --tags Key=Name,Value=MySQLInstance

echo "Waiting for MySQL instance to be running..."
aws ec2 wait instance-running --instance-ids $PRIVATE_INSTANCE_ID

# Get the private IP of the MySQL instance
PRIVATE_IP=$(aws ec2 describe-instances \
  --instance-ids $PRIVATE_INSTANCE_ID \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' \
  --output text)

echo "MySQL instance is running with Private IP: $PRIVATE_IP"

# Also allow health check port in the DB security group
aws ec2 authorize-security-group-ingress \
  --group-id $DB_SG_ID \
  --protocol tcp \
  --port 8080 \
  --source-group $APP_SG_ID

# Now create the Node.js app instance with the MySQL private IP and health check logic
echo "Launching Node.js application instance in public subnet..."
PUBLIC_USER_DATA=$(cat <<'EOF'
#!/bin/bash
# Install curl and wait-for-it utility
apt-get update
apt-get install -y curl netcat

# Install Docker using official script
curl -o get-docker.sh https://get.docker.com/
bash get-docker.sh
# Start and enable Docker
systemctl start docker
systemctl enable docker
# Add default user to docker group
usermod -aG docker ubuntu

# Create health check script with proper variable handling
cat > /home/ubuntu/check-mysql.sh << 'CHECKSCRIPT'
#!/bin/bash
MYSQL_HOST=$1
MAX_RETRIES=30
RETRY_INTERVAL=10

echo "Checking MySQL availability at $MYSQL_HOST:8080/health..."
for i in $(seq 1 $MAX_RETRIES); do
  response=$(curl -s http://$MYSQL_HOST:8080/health)
  if echo "$response" | grep -q '"message": "MySQL ready"'; then
    echo "MySQL is ready at attempt $i"
    exit 0
  fi
  echo "MySQL not ready yet (attempt $i/$MAX_RETRIES). Waiting $RETRY_INTERVAL seconds..."
  sleep $RETRY_INTERVAL
done

echo "MySQL did not become ready after $MAX_RETRIES attempts"
exit 1
CHECKSCRIPT

chmod +x /home/ubuntu/check-mysql.sh

# Wait for MySQL to be ready before starting the app
echo "Waiting for MySQL to become ready at PRIVATE_IP_PLACEHOLDER..."
/home/ubuntu/check-mysql.sh PRIVATE_IP_PLACEHOLDER

# If MySQL is ready, pull and run the Node.js app
if [ $? -eq 0 ]; then
  echo "MySQL is ready - starting application"
  docker pull bikaze/getting-started-app
  docker run -d \
    --name app \
    -p 3000:3000 \
    -e MYSQL_HOST="PRIVATE_IP_PLACEHOLDER" \
    -e MYSQL_USER="root" \
    -e MYSQL_PASSWORD="secret" \
    -e MYSQL_DB="todos" \
    bikaze/getting-started-app
  
  echo "Application started successfully"
else
  echo "Failed to connect to MySQL - not starting application"
  exit 1
fi
EOF
)

# Replace the placeholder with the actual IP
PUBLIC_USER_DATA=${PUBLIC_USER_DATA//PRIVATE_IP_PLACEHOLDER/$PRIVATE_IP}

PUBLIC_INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_NAME \
  --subnet-id $PUBLIC_SUBNET_ID \
  --security-group-ids $APP_SG_ID \
  --user-data "$PUBLIC_USER_DATA" \
  --query 'Instances[0].InstanceId' \
  --output text)
aws ec2 create-tags --resources $PUBLIC_INSTANCE_ID --tags Key=Name,Value=NodeJSAppInstance

echo "Waiting for Node.js instance to be running..."
aws ec2 wait instance-running --instance-ids $PUBLIC_INSTANCE_ID

# Get public IP of app instance
PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids $PUBLIC_INSTANCE_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

echo "=== Setup Complete! ==="
echo "Node.js Application Instance:"
echo "  - Instance ID: $PUBLIC_INSTANCE_ID"
echo "  - Public IP: $PUBLIC_IP"
echo "  - Access your application at: http://$PUBLIC_IP:3000"
echo "  - SSH access: ssh -i ${KEY_NAME}.pem ubuntu@$PUBLIC_IP"
echo ""
echo "MySQL Database Instance:"
echo "  - Instance ID: $PRIVATE_INSTANCE_ID"
echo "  - Private IP: $PRIVATE_IP (used by the Node.js app for connections)"
echo "  - To access MySQL instance: First SSH to app instance, then: ssh -i ${KEY_NAME}.pem ubuntu@$PRIVATE_IP"
echo ""
echo "Database connection details:"
echo "  - Host: $PRIVATE_IP"
echo "  - Port: 3306"
echo "  - User: root"
echo "  - Password: secret"
echo "  - Database: todos"
echo ""
echo "Note: The application will wait for MySQL to be healthy before starting."
echo "This may take a few minutes after instances are reported as running."