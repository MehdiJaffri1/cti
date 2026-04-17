declare module "react-plotly.js" {
  import * as React from "react";

  interface PlotParams {
    data: any[];
    layout?: Partial<any>;
    config?: Partial<any>;
    onClick?: (event: any) => void;
    onSelected?: (event: any) => void;
    style?: React.CSSProperties;
  }

  export default class Plot extends React.Component<PlotParams> {}
}
