package com.burpmcpbridge.ui;

import burp.api.montoya.MontoyaApi;
import com.burpmcpbridge.BurpMcpBridgeExtension;
import com.burpmcpbridge.mcp.ToolRegistry;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;

public class McpBridgeTab extends JPanel {

    private final MontoyaApi api;
    private final ToolRegistry toolRegistry;
    private final BurpMcpBridgeExtension extension;

    private JTextField portField;
    private JButton startButton;
    private JButton stopButton;
    private JLabel statusLabel;
    private JTextArea logArea;
    private JCheckBox autoStartCheckbox;
    private JCheckBox allowAutoTargetCheckbox;

    public McpBridgeTab(MontoyaApi api, ToolRegistry toolRegistry, BurpMcpBridgeExtension extension) {
        this.api = api;
        this.toolRegistry = toolRegistry;
        this.extension = extension;
        createUI();
    }

    private void createUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(15, 15, 15, 15));
        setBackground(new Color(45, 45, 45));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        topPanel.setBackground(new Color(45, 45, 45));

        JLabel portLabel = new JLabel("端口:");
        portLabel.setForeground(Color.WHITE);
        topPanel.add(portLabel);

        portField = new JTextField("9877", 6);
        portField.setBackground(new Color(60, 60, 60));
        portField.setForeground(Color.WHITE);
        portField.setCaretColor(Color.WHITE);
        topPanel.add(portField);

        startButton = new JButton("启动服务");
        startButton.setBackground(new Color(46, 139, 87));
        startButton.setForeground(Color.WHITE);
        startButton.setFocusPainted(false);
        startButton.addActionListener(this::onStart);
        topPanel.add(startButton);

        stopButton = new JButton("停止服务");
        stopButton.setBackground(new Color(178, 34, 34));
        stopButton.setForeground(Color.WHITE);
        stopButton.setFocusPainted(false);
        stopButton.setEnabled(false);
        stopButton.addActionListener(this::onStop);
        topPanel.add(stopButton);

        statusLabel = new JLabel("已停止");
        statusLabel.setForeground(new Color(178, 34, 34));
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 13f));
        topPanel.add(statusLabel);

        autoStartCheckbox = new JCheckBox("加载时自动启动", false);
        autoStartCheckbox.setForeground(Color.LIGHT_GRAY);
        autoStartCheckbox.setBackground(new Color(45, 45, 45));
        topPanel.add(autoStartCheckbox);

        allowAutoTargetCheckbox = new JCheckBox("自动批准目标", false);
        allowAutoTargetCheckbox.setForeground(Color.LIGHT_GRAY);
        allowAutoTargetCheckbox.setBackground(new Color(45, 45, 45));
        topPanel.add(allowAutoTargetCheckbox);

        add(topPanel, BorderLayout.NORTH);

        JPanel infoPanel = new JPanel(new GridLayout(4, 2, 5, 5));
        infoPanel.setBackground(new Color(50, 50, 50));
        infoPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            "连接信息",
            0, 0, null, Color.WHITE
        ));

        String[][] infoData = {
            {"SSE 端点:", "http://127.0.0.1:9877/sse"},
            {"消息端点:", "http://127.0.0.1:9877/message"},
            {"健康检查:", "http://127.0.0.1:9877/health"},
            {"已注册工具:", String.valueOf(toolRegistry.getToolCount())}
        };

        for (String[] row : infoData) {
            JLabel label = new JLabel(row[0]);
            label.setForeground(Color.LIGHT_GRAY);
            infoPanel.add(label);
            JLabel value = new JLabel(row[1]);
            value.setForeground(new Color(100, 200, 255));
            infoPanel.add(value);
        }

        add(infoPanel, BorderLayout.CENTER);

        logArea = new JTextArea(8, 50);
        logArea.setBackground(new Color(30, 30, 30));
        logArea.setForeground(new Color(0, 200, 0));
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logArea.setEditable(false);
        logArea.setText("[MCP Bridge] 就绪。点击 '启动服务' 开始。\n");

        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            "服务日志",
            0, 0, null, Color.WHITE
        ));
        add(scrollPane, BorderLayout.SOUTH);
    }

    private void onStart(ActionEvent e) {
        try {
            int port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) {
                JOptionPane.showMessageDialog(this, "端口号无效 (1-65535)", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            extension.startServer(port);
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            portField.setEnabled(false);
            statusLabel.setText("运行中，端口 " + port);
            statusLabel.setForeground(new Color(46, 139, 87));
            logArea.append("[MCP Bridge] 服务已启动，端口 " + port + "\n");
            logArea.append("[MCP Bridge] SSE: http://127.0.0.1:" + port + "/sse\n");
            logArea.append("[MCP Bridge] 工具: " + toolRegistry.getToolCount() + " 个已注册\n");
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "端口必须是数字", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onStop(ActionEvent e) {
        extension.stopServer();
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        portField.setEnabled(true);
        statusLabel.setText("已停止");
        statusLabel.setForeground(new Color(178, 34, 34));
        logArea.append("[MCP Bridge] 服务已停止。\n");
    }
}