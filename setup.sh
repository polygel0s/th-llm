#!/bin/bash

set -e

echo "----[ Update and install dependencies ]----"
sudo apt update && sudo apt upgrade -y
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev swig zlib1g-dev git curl unzip

echo "----[ Download and build Zeek ]----"
cd /opt
sudo git clone --recursive https://github.com/zeek/zeek
cd zeek
sudo ./configure
sudo make -j$(nproc)
sudo make install

echo "----[ Download and build Zeek's Broker ]----"
cd /opt
sudo git clone --recursive https://github.com/zeek/broker
cd broker
sudo ./configure
sudo make -j$(nproc)
sudo make install

# Add Zeek to PATH (persistent)
if ! grep -q "/usr/local/zeek/bin" ~/.bashrc; then
  echo 'export PATH=/usr/local/zeek/bin:$PATH' >> ~/.bashrc
fi
export PATH=/usr/local/zeek/bin:$PATH

echo "----[ Verify Zeek Installation ]----"
/usr/local/zeek/bin/zeek --version

echo "----[ Zeek Configuration]----"
# Broker is built into Zeek as of recent versions
# This is only needed if you plan to use Python bindings explicitly
echo "[*] Adding custom Broker script..."

# Create broker script
cat <<EOF | sudo tee /usr/local/zeek/share/zeek/site/broker-connections.zeek > /dev/null
global conn_topic = "/content";

global conn_event: event(orig_h:addr, orig_p:port, resp_h:addr, resp_p:port, content:string, ts:time);

function output(c:connection, bytes:string)
{
  print network_time();
  Broker::publish("/content", conn_event, c\$id\$orig_h, c\$id\$orig_p, c\$id\$resp_h, c\$id\$resp_p, bytes, c\$start_time);
}

event tcp_packet(c: connection, is_orig:bool, flags:string, seq:count, ack:count, len:count, payload:string)
{
    output(c, string_to_ascii_hex(payload));
}

global new_conn_added: event(c: connection);
global conn_removed: event(c: connection);

event new_connection(c: connection) {
        print network_time(), "NEW", c\$id, c\$start_time;
        Broker::publish(conn_topic, new_conn_added, c);
}
event connection_state_remove(c: connection) {
        print "REMOVE", c\$id, c\$start_time;
        Broker::publish(conn_topic, conn_removed, c);
}

event Pcap::file_done(path: string) {
        print network_time(), "PCAP", path;
        terminate();
}

event zeek_init()
{
        Broker::listen("127.0.0.1", 9999/tcp);
        Broker::subscribe(conn_topic);
}
EOF

# Load it in local.zeek if not already present
if ! grep -q "broker-connections" /usr/local/zeek/share/zeek/site/local.zeek; then
    echo "@load ./broker-connections" | sudo tee -a /usr/local/zeek/share/zeek/site/local.zeek > /dev/null
    echo "[*] Loaded broker-conn.zeek in local.zeek"
fi

echo "@load frameworks/files/extract-all-files" | sudo tee -a /usr/local/zeek/share/zeek/site/local.zeek > /dev/null
echo "[*] Added file extraction"

echo "[*] Using interface: ens34"

NODE_CFG="/usr/local/zeek/etc/node.cfg"
sudo tee "$NODE_CFG" > /dev/null <<EOF
[zeek]
type=standalone
host=localhost
interface=ens34
EOF

echo "[*] Setting up zeekctl..."

cd /usr/local/zeek
sudo bin/zeekctl deploy || true  # ensure base structure exists
sudo bin/zeekctl install

echo "----[ Install Ollama ]----"
curl -fsSL https://ollama.com/install.sh | sh

echo "----[ Add Ollama to systemd and start ]----"
sudo systemctl enable ollama
sudo systemctl start ollama

echo "----[ Pull lightweight LLaMA3 model (8B) ]----"
ollama pull llama3:8b

echo "----[ Step 8: Run LLaMA3 lightweight model in background ]----"
# Optional: run once in background to preload it and confirm functionality
nohup ollama run llama3:8b > /tmp/ollama_model_output.log 2>&1 &

echo "----[ Verify Ollama Installation ]----"
ollama --version

sudo apt install python3-pip yara tcpreplay 
pip install --upgrade pip

pip install \
    numpy \
    pandas \
    matplotlib \
    plotly \
    dash \
    scikit-learn \
    --quiet

echo "----[ Setup complete! ]----"
