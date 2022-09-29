const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");



const popup = {
  mode: "development",
  entry: {
    popup: path.resolve(__dirname, "src/popup.js"), // エントリーポイント修正
  },
  output: {
    path: path.resolve(__dirname, "dist/"),
    filename: "[name].js",
  },
  resolve: {
    modules: [path.resolve(__dirname, "./node_modules")],
    extensions: [".js", ".ts", ".tsx"], // ts, tsx 追加
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: path.resolve(__dirname, "src/popup.html"),
      filename: "popup.html"
    }),
  ],
  devtool: 'cheap-module-source-map'
};

const options = {
  mode: "development",
  entry: {
    options: path.resolve(__dirname, "src/options.js"), // エントリーポイント修正
  },
  output: {
    path: path.resolve(__dirname, "dist/"),
    filename: "[name].js",
  },
  resolve: {
    modules: [path.resolve(__dirname, "./node_modules")],
    extensions: [".js", ".ts", ".tsx"], // ts, tsx 追加
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: path.resolve(__dirname, "src/options.html"),
      filename: "options.html"
    }),
  ],
  devtool: 'cheap-module-source-map'
};

const scripting = {
  mode: "development",
  entry: {
    popup_script: path.resolve(__dirname, "src/popup_script.js"), // エントリーポイント修正
  },
  output: {
    path: path.resolve(__dirname, "dist/"),
    filename: "[name].js",
  },
  resolve: {
    modules: [path.resolve(__dirname, "./node_modules")],
    extensions: [".js", ".ts", ".tsx"], // ts, tsx 追加
  },
  devtool: 'cheap-module-source-map'
};

module.exports = [popup, options, scripting];